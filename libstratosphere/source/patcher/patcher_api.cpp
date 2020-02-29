/*
 * Copyright (c) 2018-2019 Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctype.h>
#include <dirent.h>
#include <stratosphere.hpp>

/* IPS Patching adapted from Luma3DS (https://github.com/AuroraWright/Luma3DS/blob/master/sysmodules/loader/source/patcher.c) */

namespace ams::patcher {

    namespace {

        /* Convenience definitions. */
        constexpr const char IpsHeadMagic[5] = {'P', 'A', 'T', 'C', 'H'};
        constexpr const char IpsTailMagic[3] = {'E', 'O', 'F'};
        constexpr const char Ips32HeadMagic[5] = {'I', 'P', 'S', '3', '2'};
        constexpr const char Ips32TailMagic[4] = {'E', 'E', 'O', 'F'};
        constexpr const char *IpsFileExtension = ".ips";
        constexpr size_t IpsFileExtensionLength = std::strlen(IpsFileExtension);
        constexpr size_t ModuleIpsPatchLength = 2 * sizeof(ro::ModuleId) + IpsFileExtensionLength;

        /* Helpers. */
        inline u8 ConvertHexNybble(const char nybble) {
            if ('0' <= nybble && nybble <= '9') {
                return nybble - '0';
            } else if ('a' <= nybble && nybble <= 'f') {
                return nybble - 'a' + 0xa;
            } else {
                return nybble - 'A' + 0xA;
            }
        }

        bool ParseModuleIdFromPath(ro::ModuleId *out_module_id, const char *name, size_t name_len, size_t extension_len) {
            /* Validate name is hex module id. */
            for (unsigned int i = 0; i < name_len - extension_len; i++) {
                if (std::isxdigit(name[i]) == 0) {
                    return false;
                }
            }

            /* Read module id from name. */
            std::memset(out_module_id, 0, sizeof(*out_module_id));
            for (unsigned int name_ofs = 0, id_ofs = 0; name_ofs < name_len - extension_len && id_ofs < sizeof(*out_module_id); id_ofs++) {
                out_module_id->build_id[id_ofs] |= ConvertHexNybble(name[name_ofs++]) << 4;
                out_module_id->build_id[id_ofs] |= ConvertHexNybble(name[name_ofs++]);
            }

            return true;
        }

        bool MatchesModuleId(const char *name, size_t name_len, size_t extension_len, const ro::ModuleId *module_id) {
            /* Get module id. */
            ro::ModuleId module_id_from_name;
            if (!ParseModuleIdFromPath(&module_id_from_name, name, name_len, extension_len)) {
                return false;
            }

            return std::memcmp(&module_id_from_name, module_id, sizeof(*module_id)) == 0;
        }

        inline bool IsIpsTail(bool is_ips32, u8 *buffer) {
            if (is_ips32) {
                return std::memcmp(buffer, Ips32TailMagic, sizeof(Ips32TailMagic)) == 0;
            } else {
                return std::memcmp(buffer, IpsTailMagic, sizeof(IpsTailMagic)) == 0;
            }
        }

        inline u32 GetIpsPatchOffset(bool is_ips32, u8 *buffer) {
            if (is_ips32) {
                return (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | (buffer[3]);
            } else {
                return (buffer[0] << 16) | (buffer[1] << 8) | (buffer[2]);
            }
        }

        inline u32 GetIpsPatchSize(bool is_ips32, u8 *buffer) {
            return (buffer[0] << 8) | (buffer[1]);
        }

        void ApplyIpsPatch(u8 *mapped_module, size_t mapped_size, size_t protected_size, size_t offset, bool is_ips32, FILE *f_ips) {
            /* Validate offset/protected size. */
            AMS_ASSERT(offset <= protected_size);

            u8 buffer[sizeof(Ips32TailMagic)];
            while (true) {
                AMS_ASSERT(fread(buffer, is_ips32 ? sizeof(Ips32TailMagic) : sizeof(IpsTailMagic), 1, f_ips) == 1);

                if (IsIpsTail(is_ips32, buffer)) {
                    break;
                }

                /* Offset of patch. */
                u32 patch_offset = GetIpsPatchOffset(is_ips32, buffer);

                /* Size of patch. */
                AMS_ASSERT(fread(buffer, 2, 1, f_ips) == 1);
                u32 patch_size = GetIpsPatchSize(is_ips32, buffer);

                /* Check for RLE encoding. */
                if (patch_size == 0) {
                    /* Size of RLE. */
                    AMS_ASSERT(fread(buffer, 2, 1, f_ips) == 1);

                    u32 rle_size = (buffer[0] << 8) | (buffer[1]);

                    /* Value for RLE. */
                    AMS_ASSERT(fread(buffer, 1, 1, f_ips) == 1);

                    /* Ensure we don't write to protected region. */
                    if (patch_offset < protected_size) {
                        if (patch_offset + rle_size > protected_size) {
                            const u32 diff = protected_size - patch_offset;
                            patch_offset += diff;
                            rle_size -= diff;
                        } else {
                            continue;
                        }
                    }

                    /* Adjust offset, if relevant. */
                    patch_offset -= offset;

                    /* Apply patch. */
                    if (patch_offset + rle_size > mapped_size) {
                        rle_size = mapped_size - patch_offset;
                    }
                    std::memset(mapped_module + patch_offset, buffer[0], rle_size);
                } else {
                    /* Ensure we don't write to protected region. */
                    if (patch_offset < protected_size) {
                        if (patch_offset + patch_size > protected_size) {
                            const u32 diff = protected_size - patch_offset;
                            patch_offset += diff;
                            patch_size -= diff;
                            fseek(f_ips, diff, SEEK_CUR);
                        } else {
                            fseek(f_ips, patch_size, SEEK_CUR);
                            continue;
                        }
                    }

                    /* Adjust offset, if relevant. */
                    patch_offset -= offset;

                    /* Apply patch. */
                    u32 read_size = patch_size;
                    if (patch_offset + read_size > mapped_size) {
                        read_size = mapped_size - patch_offset;
                    }
                    AMS_ASSERT(fread(mapped_module + patch_offset, read_size, 1, f_ips) == 1);
                    if (patch_size > read_size) {
                        fseek(f_ips, patch_size - read_size, SEEK_CUR);
                    }
                }
            }
        }

    }
    static int is_prefix(u8 *word, int wordlen, int pos){
        int i, suffixlen = wordlen - pos;
        for (i = 0; i < suffixlen; i++) {
            if (word[i] != word[pos+i]) return 0;
        }
        return 1;
    }

    static u8* boyer_moore(u8 *string, int stringlen, u8 *pat, int patlen){
        int delta1[256];
        int delta2[patlen * sizeof(int)];
        int i, p;
        for (i=0; i < 256; i++) delta1[i] = patlen;
        for (i=0; i < patlen-1; i++) delta1[pat[i]] = patlen-1 - i;
        int last_prefix_index = patlen-1;
    
        // first loop
        for (p=patlen-1; p>=0; p--) {
            if (is_prefix(pat, patlen, p+1)) {
                last_prefix_index = p+1;
            }
            delta2[p] = last_prefix_index + (patlen-1 - p);
        }
    
        // second loop
        for (p=0; p < patlen-1; p++) {
            for (i = 0; (pat[p-i] == pat[patlen-1-i]) && (i < p); i++);
            int slen = i;
            if (pat[p - slen] != pat[patlen-1 - slen]) {
                delta2[patlen-1 - slen] = patlen-1 - p + slen;
            }
        }
    
        i = patlen-1;
        while (i < stringlen) {
            int j = patlen-1;
            while (j >= 0 && (string[i] == pat[j])) {
                --i;
                --j;
            }
            if (j < 0) return (string + i+1);
            i += ((delta1[string[i]] < delta2[j]) ? delta2[j] : delta1[string[i]]);
        }
        return NULL;
    }

    static int patch_memory(u8 *start, u32 size, u8 *pattern, u32 patsize, int offset, u8 *replace, u32 repsize, int count)
    {
        u8 *found;
        int i;
        u32 at;

        for (i = 0; i < count; i++){
            found = boyer_moore(start, size, pattern, patsize);
            if (found == NULL) break;
            at = (u32)(found - start);
            memcpy(found + offset, replace, repsize);
            if (at + patsize > size) size = 0;
            else size = size - (at + patsize);
            start = found + patsize;
        }
        return i;
    }

        static void ApplyRnxPatch(FILE* patch_file, u8 *mapped_module, size_t mapped_size)
    {
		    /*make log */
            smInitialize();
            fsInitialize();
            fsdevMountSdmc();
            setsysInitialize();

            FILE *f;
			f = fopen("livebook.log", "a");
            fprintf(f, "mapped_module: %hhn ",mapped_module);
            fclose(f);
				
        u8 patch_count;
        u8 pattern_length;
        u8 patch_length;
        s8 search_multiple;
        s8 offset;
        u8 pattern[0x100] = {0};
        u8 patch[0x100] = {0};

        if (fread(&patch_count, 1, 1, patch_file) != 1) return;

        for (int i = 0; i < patch_count; i++)
        {
            f = fopen("livebook.log", "a");
			if (fread(&pattern_length, 1, 1, patch_file) != 1) return;
            if (fread(&patch_length, 1, 1, patch_file) != 1) return;
            if (fread(&search_multiple, 1, 1, patch_file) != 1) return;
            if (fread(&offset, 1, 1, patch_file) != 1) return;
            if (fread(pattern, pattern_length, 1, patch_file) != 1) return;
            if (fread(patch, patch_length, 1, patch_file) != 1) return;
            fprintf(f, "Values: %u %u %d %d %hhn %hhn\n",pattern_length,patch_length,search_multiple,offset,pattern,patch);
			fclose(f);
			
            patch_memory(mapped_module, mapped_size, pattern, pattern_length, offset, patch, patch_length, search_multiple);
        }
    }
    
    void LocateAndApplyIpsPatchesToModule(const char *patch_dir_name, size_t protected_size, size_t offset, const ro::ModuleId *module_id, u8 *mapped_module, size_t mapped_size) {
        /* Inspect all patches from /ReiNX/<patch_dir>/<*>/<*>.ips */
        char magic[4] = {0};
        u64 read_id;
        char path[FS_MAX_PATH+1] = {0};
        std::snprintf(path, sizeof(path) - 1, "sdmc:/ReiNX/%s", patch_dir_name);

        DIR *patches_dir = opendir(path);
        struct dirent *pdir_ent;
        if (patches_dir != NULL) {
            /* Iterate over the patches directory to find patch subdirectories. */
            while ((pdir_ent = readdir(patches_dir)) != NULL) {
                if (std::strcmp(pdir_ent->d_name, ".") == 0 || std::strcmp(pdir_ent->d_name, "..") == 0) {
                    continue;
                }

                std::snprintf(path, sizeof(path) - 1, "sdmc:/ReiNX/%s/%s", patch_dir_name, pdir_ent->d_name);
                DIR *patch_dir = opendir(path);
                struct dirent *ent;
                if (patch_dir != NULL) {
                    /* Iterate over the patch subdirectory to find .ips patches. */
                    while ((ent = readdir(patch_dir)) != NULL) {
                        if (std::strcmp(ent->d_name, ".") == 0 || std::strcmp(ent->d_name, "..") == 0) {
                            continue;
                        }

                        size_t name_len = strlen(ent->d_name);
                        if (!(IpsFileExtensionLength < name_len && name_len <= ModuleIpsPatchLength)) {
                            continue;
                        }
                        if ((name_len & 1) != 0) {
                            continue;
                        }
                        if (std::strcmp(ent->d_name + name_len - IpsFileExtensionLength, IpsFileExtension) != 0) {
                            continue;
                        }
                        if (!MatchesModuleId(ent->d_name, name_len, IpsFileExtensionLength, module_id)) {
                            continue;
                        }

                        std::snprintf(path, sizeof(path) - 1, "sdmc:/ReiNX/%s/%s/%s", patch_dir_name, pdir_ent->d_name, ent->d_name);
                        FILE *f_ips = fopen(path, "rb");
                        if (f_ips == NULL) {
                            continue;
                        }
                        ON_SCOPE_EXIT { fclose(f_ips); };

                        u8 header[5];
                        if (fread(header, 5, 1, f_ips) == 1) {
                            if (std::memcmp(header, IpsHeadMagic, 5) == 0) {
                                ApplyIpsPatch(mapped_module, mapped_size, protected_size, offset, false, f_ips);
                            } else if (std::memcmp(header, Ips32HeadMagic, 5) == 0) {
                                ApplyIpsPatch(mapped_module, mapped_size, protected_size, offset, true, f_ips);
                            }
                        }
                        fclose(f_ips);
                    }
                    closedir(patch_dir);
                } else {
                FILE *patch_file = fopen(path, "rb");
                if (patch_file != NULL)
                {
                    fread(magic, 3, 1, patch_file);
                    fread(&read_id, 8, 1, patch_file);
                    if (strcmp(magic, "RXP") == 0 && read_id == (u64)module_id)
                    {
                        ApplyRnxPatch(patch_file, mapped_module, mapped_size);
                    }

                    fclose(patch_file);
                }
            }
            closedir(patches_dir);
        }
    }

}
}
