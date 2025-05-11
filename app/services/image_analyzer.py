import docker
import json
import os
import tempfile
import tarfile
from pathlib import Path
import concurrent.futures
from logger import logger

class ContainerAnalyzer:
    def __init__(self):
        self.client = docker.from_env()
        
        # Define paths to check once, reuse everywhere
        self.shell_paths = [
            "bin/sh", "bin/bash", "bin/dash", "bin/zsh", "bin/ash",
            "usr/bin/sh", "usr/bin/bash", "usr/bin/ash"
        ]
        
        self.package_manager_paths = [
            "usr/bin/apt", "usr/bin/apt-get", "usr/bin/dnf", 
            "usr/bin/yum", "usr/bin/apk"
        ]
        
        self.os_indicator_files = [
            "etc/os-release",
            "etc/passwd", "etc/group", "etc/shadow",
            "var/log", "var/cache",
            "etc/alpine-release"
        ]
    
    def analyze_image(self, image_name):
        """
        Efficiently analyze a Docker image without running it
        Returns a dictionary with analysis results, image_tar_path, and the TemporaryDirectory manager object.
        """
        temp_dir_manager = tempfile.TemporaryDirectory()
        temp_dir = temp_dir_manager.name
        image_tar_path_for_return = None # Initialize

        try:
            # Pull the image if not already present
            try:
                image = self.client.images.get(image_name)
            except docker.errors.ImageNotFound:
                print(f"Pulling image {image_name}...")
                try:
                    image = self.client.images.pull(image_name)
                except docker.errors.APIError as e:
                    print(f"Error pulling image {image_name}: {e}")
                    temp_dir_manager.cleanup()
                    return {
                        "image_name": image_name, "is_rootless": None, "is_shellless": None,
                        "is_distroless": None, "error": str(e), "details": {},
                        "image_tar_path": None, "_temp_dir_manager_obj": None
                    }

            if not image:
                print(f"Image {image_name} could not be obtained.")
                temp_dir_manager.cleanup()
                return {
                    "image_name": image_name, "is_rootless": None, "is_shellless": None,
                    "is_distroless": None, "error": "Image could not be obtained after attempting pull.",
                    "details": {}, "image_tar_path": None, "_temp_dir_manager_obj": None
                }

            # Get image details
            try:
                image_details = self.client.api.inspect_image(image.id)
            except docker.errors.APIError as e:
                print(f"Error inspecting image {image.id} ({image_name}): {e}")
                temp_dir_manager.cleanup()
                return {
                    "image_name": image_name, "is_rootless": None, "is_shellless": None,
                    "is_distroless": None, "error": f"Failed to inspect image: {str(e)}",
                    "details": {"image_id": image.id if image else "Unknown"},
                    "image_tar_path": None, "_temp_dir_manager_obj": None
                }

            # Filesystem analysis
            rootfs_path, image_tar_path_for_return = self._extract_image_efficiently(image.id, temp_dir)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                has_shell_future = executor.submit(self._has_shell, rootfs_path)
                has_package_mgr_future = executor.submit(self._has_package_manager, rootfs_path)
                file_count_future = executor.submit(self._count_files_efficiently, rootfs_path)
                distro_info_future = executor.submit(self._get_distribution_info, rootfs_path)
                
                found_shell_path = has_shell_future.result()
                found_package_manager_path = has_package_mgr_future.result()
                file_count = file_count_future.result()
                distribution_info = distro_info_future.result()
            
            is_distroless_result = self._is_distroless(
                image_name, image_details, rootfs_path,
                bool(found_shell_path), bool(found_package_manager_path), file_count
            )
            
            is_rootless_val = self._is_rootless(image_details)
            
            return {
                "image_name": image_name,
                "is_rootless": is_rootless_val,
                "is_shellless": not bool(found_shell_path),
                "is_distroless": is_distroless_result,
                "details": {
                    "has_shell": bool(found_shell_path), "found_shell_path": found_shell_path,
                    "has_package_manager": bool(found_package_manager_path),
                    "found_package_manager_path": found_package_manager_path,
                    "user": image_details.get("Config", {}).get("User", ""),
                    "file_count": file_count, "image_id": image.id,
                    "distribution_info": distribution_info
                },
                "error": None,
                "image_tar_path": image_tar_path_for_return,
                "_temp_dir_manager_obj": temp_dir_manager
            }

        except Exception as e:
            print(f"Error during image analysis for {image_name}: {e}")
            # temp_dir_manager will be returned for cleanup by the caller even in case of error
            is_rootless_val = self._is_rootless(image_details) if 'image_details' in locals() else None
            distribution_info = None
            return {
                "image_name": image_name,
                "is_rootless": is_rootless_val,
                "is_shellless": None, "is_distroless": None,
                "error": f"Filesystem analysis failed: {str(e)}",
                "details": {
                    "user": image_details.get("Config", {}).get("User", "") if 'image_details' in locals() else "",
                    "image_id": image.id if 'image' in locals() and image else "Unknown",
                    "distribution_info": distribution_info
                },
                "image_tar_path": image_tar_path_for_return, # May be None or have a path
                "_temp_dir_manager_obj": temp_dir_manager # Crucial for cleanup by caller
            }
    
    def _extract_image_efficiently(self, image_id, temp_dir):
        """
        Extracts image layers to rootfs and saves image.tar in temp_dir.
        Returns rootfs_path and image_tar_path.
        """
        image_tar_path = os.path.join(temp_dir, "image.tar")
        try:
            with open(image_tar_path, 'wb') as f:
                for chunk in self.client.api.get_image(image_id):
                    f.write(chunk)
        except docker.errors.APIError as e:
            print(f"Docker API error while getting image {image_id} for extraction: {e}")
            raise 

        rootfs_path = os.path.join(temp_dir, "rootfs")
        os.makedirs(rootfs_path, exist_ok=True)
        
        manifest_path = None # Initialize
        try:
            with tarfile.open(image_tar_path, 'r') as tar: # First pass to find manifest.json
                for member in tar.getmembers():
                    if member.name == 'manifest.json':
                        tar.extract(member, path=temp_dir)
                        manifest_path = os.path.join(temp_dir, "manifest.json")
                        break
                    # Some images might have a differently named JSON config file at the root
                    # that acts as a manifest, often image_id.json or similar.
                    # This is less standard than manifest.json for 'docker save' tars.
                    elif member.name.endswith('.json') and '/' not in member.name: 
                         tar.extract(member, path=temp_dir)
                         # Heuristic: assume the first root-level JSON is the one we want if no manifest.json
                         if manifest_path is None: # Prioritize manifest.json if found later
                            manifest_path = os.path.join(temp_dir, member.name)


        except Exception as e:
            print(f"Warning: Could not extract manifest/config from initial tar scan of {image_id}: {e}")
            # Continue to fallback if manifest extraction failed

        manifest = None
        if manifest_path and os.path.exists(manifest_path):
            try:
                with open(manifest_path, 'r') as f:
                    manifest = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError) as e:
                print(f"Manifest file {manifest_path} not found or invalid for {image_id}, attempting fallback extraction: {e}")
                # Fallback will use image_tar_path
        else: # No manifest_path determined or file doesn't exist
             print(f"Manifest file not found after initial scan for {image_id}, attempting fallback extraction.")


        if manifest and isinstance(manifest, list) and len(manifest) > 0 and "Layers" in manifest[0]:
            layers_paths_in_manifest = manifest[0].get("Layers", [])
            
            if not os.path.exists(image_tar_path):
                 print(f"CRITICAL: image.tar expected at {image_tar_path} but not found before layer extraction. Aborting layer processing.")
                 # Fallback is unlikely to succeed if image.tar isn't there.
                 # We will proceed to the fallback call below, but it will likely also fail.
            else:
                for layer_filename_in_manifest in layers_paths_in_manifest: 
                    actual_extracted_layer_tar_path = os.path.join(temp_dir, layer_filename_in_manifest)
                    try:
                        with tarfile.open(image_tar_path, 'r') as image_tar_file_obj:
                            member_found = False
                            for member in image_tar_file_obj.getmembers():
                                if member.name == layer_filename_in_manifest:
                                    image_tar_file_obj.extract(member, path=temp_dir)
                                    member_found = True
                                    break
                            if not member_found:
                                print(f"Warning: Layer {layer_filename_in_manifest} not found in image tar for {image_id}.")
                                continue
                    except Exception as e:
                        print(f"Error extracting layer {layer_filename_in_manifest} from image tar: {e}")
                        continue

                    if not os.path.exists(actual_extracted_layer_tar_path):
                        print(f"Warning: Extracted layer tarball {actual_extracted_layer_tar_path} was expected but does not exist.")
                        continue
                    
                    self._selective_layer_extract(actual_extracted_layer_tar_path, rootfs_path)
                    if os.path.exists(actual_extracted_layer_tar_path): 
                        os.unlink(actual_extracted_layer_tar_path) # Clean up individual layer tar after processing
        else: # manifest is None, or not list, or no Layers
            print(f"Manifest for {image_id} does not contain layers or is not in expected format. Attempting fallback extraction from {image_tar_path}.")
            self._extract_image_fallback(image_tar_path, rootfs_path)

        # DO NOT UNLINK image_tar_path here. Caller manages the temp_dir.
        return rootfs_path, image_tar_path
    
    def _extract_image_fallback(self, image_tar_path, rootfs_path):
        """
        Fallback method for extracting image content by iterating through all .tar files
        which might be layers within the main image.tar.
        """
        print(f"Executing fallback extraction for {image_tar_path}")
        if not os.path.exists(image_tar_path):
            print(f"Fallback extraction cannot proceed: main image tarball {image_tar_path} does not exist.")
            return rootfs_path # Or raise specific error

        with tarfile.open(image_tar_path, 'r') as tar:
            for member in tar.getmembers():
                # Check if the member is a tar file itself (a layer)
                if member.name.endswith(('.tar', '.tar.gz', '.tgz')):
                    try:
                        # Extract the layer tarball to a temporary file-like object
                        layer_file_obj = tar.extractfile(member)
                        if layer_file_obj:
                            # Open the extracted layer tarball
                            with tarfile.open(fileobj=layer_file_obj) as layer_tar:
                                self._selective_layer_extract(layer_tar, rootfs_path, is_fileobj=True)
                    except Exception as e:
                        print(f"Fallback: Error processing member {member.name}: {e}")
                        # Continue to try other members
        return rootfs_path

    def _selective_layer_extract(self, layer_tar_source, rootfs_path, is_fileobj=False):
        """
        Only extract files we need to check for our analysis from a given layer tar.
        Also extracts symlink targets if the symlink itself is matched.
        """
        # print(f"[_selective_layer_extract] Source: {layer_tar_source if not is_fileobj else 'fileobj'}, Target: {rootfs_path}")
        logger.debug(f"[_selective_layer_extract] Source: {layer_tar_source if not is_fileobj else 'fileobj'}, Target: {rootfs_path}")
        try:
            tar_opener = tarfile.open(name=None if is_fileobj else layer_tar_source, fileobj=layer_tar_source if is_fileobj else None, mode='r')
            
            with tar_opener as tar:
                # Store all members for potential target lookup
                members_in_layer = tar.getmembers()
                members_in_layer_dict = {m.name.lstrip('./'): m for m in members_in_layer}
                member_names_in_layer = list(members_in_layer_dict.keys())
                # print(f"[_selective_layer_extract] Members found in layer: {member_names_in_layer[:20]}... (total {len(member_names_in_layer)})")
                logger.debug(f"[_selective_layer_extract] Members found in layer: {member_names_in_layer[:20]}... (total {len(member_names_in_layer)})")

                initial_matches = []
                paths_to_check = self.shell_paths + self.package_manager_paths + self.os_indicator_files
                # print(f"[_selective_layer_extract] Paths to check in this layer: {paths_to_check}")
                logger.debug(f"[_selective_layer_extract] Paths to check in this layer: {paths_to_check}")

                for member in members_in_layer:
                    member_name_normalized = member.name.lstrip('./')
                    if member.isfile() or member.issym():
                        for path_to_check in paths_to_check:
                            if member_name_normalized == path_to_check:
                                # print(f"[_selective_layer_extract] Found initial match: {member.name} (Type: {'File' if member.isfile() else 'Symlink' if member.issym() else 'Other'}) for path: {path_to_check}")
                                logger.debug(f"[_selective_layer_extract] Found initial match: {member.name} (Type: {'File' if member.isfile() else 'Symlink' if member.issym() else 'Other'}) for path: {path_to_check}")
                                initial_matches.append(member)
                                break 
                
                # Add symlink targets if they exist in this layer
                final_members_to_extract = list(initial_matches)
                targets_to_find = set()
                for member in initial_matches:
                    if member.issym() and member.linkname:
                        # Normalize linkname? Assume relative for now.
                        target_name = member.linkname.lstrip('./') 
                        targets_to_find.add(target_name)
                
                # print(f"[_selective_layer_extract] Symlink targets to look for in this layer: {targets_to_find}")
                logger.debug(f"[_selective_layer_extract] Symlink targets to look for in this layer: {targets_to_find}")
                for target_name in targets_to_find:
                    target_member = members_in_layer_dict.get(target_name)
                    if target_member:
                        # Check if already included to avoid duplicates (though tar.extract handles it)
                        is_already_included = any(m.name == target_member.name for m in final_members_to_extract)
                        if not is_already_included:
                            # print(f"[_selective_layer_extract] Adding symlink target member: {target_member.name}")
                            logger.debug(f"[_selective_layer_extract] Adding symlink target member: {target_member.name}")
                            final_members_to_extract.append(target_member)
                    else:
                         print(f"Warning: Symlink target '{target_name}' was not found in the same layer.")

                # Separate members into symlinks and non-symlinks
                symlink_members = [m for m in final_members_to_extract if m.issym()]
                non_symlink_members = [m for m in final_members_to_extract if not m.issym()]

                # Extract non-symlinks first (including potential targets)
                if non_symlink_members:
                    # print(f"[_selective_layer_extract] Attempting to extract non-symlinks: {[m.name for m in non_symlink_members]}")
                    logger.debug(f"[_selective_layer_extract] Attempting to extract non-symlinks: {[m.name for m in non_symlink_members]}")
                    for member_to_extract in non_symlink_members:
                        try:
                            tar.extract(member_to_extract, path=rootfs_path)
                            extracted_file_path = os.path.join(rootfs_path, member_to_extract.name.lstrip('./'))
                            # Log basic extraction result here
                            # print(f"[_selective_layer_extract] Extracted non-symlink {member_to_extract.name} to {extracted_file_path}. Exists: {os.path.exists(extracted_file_path)}, Executable: {os.access(extracted_file_path, os.X_OK)}")
                            logger.debug(f"[_selective_layer_extract] Extracted non-symlink {member_to_extract.name} to {extracted_file_path}. Exists: {os.path.exists(extracted_file_path)}, Executable: {os.access(extracted_file_path, os.X_OK)}")
                        except Exception as e:
                            print(f"Warning: Could not extract non-symlink {member_to_extract.name} during selective layer extract: {e}")
                
                # Extract symlinks second, hoping targets now exist
                if symlink_members:
                    # print(f"[_selective_layer_extract] Attempting to extract symlinks: {[m.name for m in symlink_members]}")
                    logger.debug(f"[_selective_layer_extract] Attempting to extract symlinks: {[m.name for m in symlink_members]}")
                    for member_to_extract in symlink_members:
                        try:
                            tar.extract(member_to_extract, path=rootfs_path) # tarfile handles creating the symlink file
                            extracted_file_path = os.path.join(rootfs_path, member_to_extract.name.lstrip('./'))
                            symlink_exists = os.path.lexists(extracted_file_path)
                            # Log only symlink creation success here
                            # print(f"[_selective_layer_extract] Created symlink {member_to_extract.name} at {extracted_file_path}. Link Exists: {symlink_exists}")
                            logger.debug(f"[_selective_layer_extract] Created symlink {member_to_extract.name} at {extracted_file_path}. Link Exists: {symlink_exists}")
                        except Exception as e:
                            print(f"Warning: Could not extract symlink {member_to_extract.name} during selective layer extract: {e}")
                # Removed the 'Re-checking' block as checks are now robust in _has_shell

        except (tarfile.ReadError, EOFError, IOError, FileNotFoundError) as e:
            print(f"Warning: Skipping layer due to error: {e} (Source: {layer_tar_source if not is_fileobj else 'fileobj'})")
            pass
    
    def _is_rootless(self, image_details):
        """
        Check if image is configured to run as non-root
        """
        user = image_details.get("Config", {}).get("User", "")
        
        # Check numeric and string user representations
        if user:
            # If it's numeric and not 0
            if user.isdigit() and user != "0":
                return True
            # If it's a string and not root
            if not user.isdigit() and user.lower() != "root": # case-insensitive for "root"
                return True
        
        return False # Default to not rootless if user is empty, "0", or "root"
    
    def _has_shell(self, rootfs_path):
        """
        Check for existence of any executable shell, handling symlinks explicitly.
        Returns the path of the first found executable shell, or None.
        """
        # print(f"[_has_shell] Checking for shells in: {rootfs_path}")
        logger.debug(f"[_has_shell] Checking for shells in: {rootfs_path}")
        # print(f"[_has_shell] Shell paths to check: {self.shell_paths}")
        logger.debug(f"[_has_shell] Shell paths to check: {self.shell_paths}")
        for shell_path in self.shell_paths:
            full_path = os.path.join(rootfs_path, shell_path)
            # print(f"[_has_shell] Checking path: {full_path}")
            logger.debug(f"[_has_shell] Checking path: {full_path}")
            
            if not os.path.lexists(full_path):
                # print(f"[_has_shell]   - Path does not exist (lexists=False)")
                logger.debug(f"[_has_shell]   - Path does not exist (lexists=False)")
                continue

            if not os.path.islink(full_path):
                if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                    # print(f"[_has_shell]   - Found executable file: {shell_path}") # Log relative path found
                    logger.debug(f"[_has_shell]   - Found executable file: {shell_path}") # Log relative path found
                    return shell_path # Return the matched path
                # else:
                    # print(f"[_has_shell]   - Is file, but not executable (isfile={os.path.isfile(full_path)}, access={os.access(full_path, os.X_OK)})")
                logger.debug(f"[_has_shell]   - Is file, but not executable (isfile={os.path.isfile(full_path)}, access={os.access(full_path, os.X_OK)})")
            else:
                # print(f"[_has_shell]   - Is symlink.")
                logger.debug(f"[_has_shell]   - Is symlink.")
                try:
                    link_target_name = os.readlink(full_path)
                    # print(f"[_has_shell]     - Link target name: {link_target_name}")
                    logger.debug(f"[_has_shell]     - Link target name: {link_target_name}")
                    target_path = None
                    if os.path.isabs(link_target_name):
                        target_path = os.path.join(rootfs_path, link_target_name.lstrip('/'))
                    else:
                        symlink_dir = os.path.dirname(full_path)
                        target_path = os.path.normpath(os.path.join(symlink_dir, link_target_name))
                    
                    # print(f"[_has_shell]     - Calculated target path: {target_path}")
                    logger.debug(f"[_has_shell]     - Calculated target path: {target_path}")
                    if os.path.exists(target_path) and not os.path.isdir(target_path) and os.access(target_path, os.X_OK):
                         # print(f"[_has_shell]   - Found symlink pointing to executable target: {shell_path} -> {target_path}")
                         logger.debug(f"[_has_shell]   - Found symlink pointing to executable target: {shell_path} -> {target_path}")
                         return shell_path # Return the matched path (the symlink itself)
                    # else:
                         # print(f"[_has_shell]     - Target status: Exists={os.path.exists(target_path)}, IsDir={os.path.isdir(target_path)}, Executable={os.access(target_path, os.X_OK)}")
                    logger.debug(f"[_has_shell]     - Target status: Exists={os.path.exists(target_path)}, IsDir={os.path.isdir(target_path)}, Executable={os.access(target_path, os.X_OK)}")
                except OSError as e:
                    print(f"[_has_shell]     - Error reading link or checking target: {e}")
        
        # print("[_has_shell] No executable shell found after checking all paths.")
        logger.debug("[_has_shell] No executable shell found after checking all paths.")
        return None # Return None if no shell found
    
    def _has_package_manager(self, rootfs_path):
        """
        Check for existence of any executable package manager, handling symlinks explicitly.
        Returns the path of the first found executable package manager, or None.
        """
        # print(f"[_has_package_manager] Checking for package managers in: {rootfs_path}")
        logger.debug(f"[_has_package_manager] Checking for package managers in: {rootfs_path}")
        # print(f"[_has_package_manager] Paths to check: {self.package_manager_paths}")
        logger.debug(f"[_has_package_manager] Paths to check: {self.package_manager_paths}")
        for pkg_mgr_path in self.package_manager_paths:
            full_path = os.path.join(rootfs_path, pkg_mgr_path)
            # print(f"[_has_package_manager] Checking path: {full_path}")
            logger.debug(f"[_has_package_manager] Checking path: {full_path}")
            
            if not os.path.lexists(full_path):
                # print(f"[_has_package_manager]   - Path does not exist (lexists=False)")
                logger.debug(f"[_has_package_manager]   - Path does not exist (lexists=False)")
                continue

            if not os.path.islink(full_path):
                if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                    # print(f"[_has_package_manager]   - Found executable file: {pkg_mgr_path}")
                    logger.debug(f"[_has_package_manager]   - Found executable file: {pkg_mgr_path}")
                    return pkg_mgr_path # Return the matched path
                # else:
                    # print(f"[_has_package_manager]   - Is file, but not executable (isfile={os.path.isfile(full_path)}, access={os.access(full_path, os.X_OK)})")
                logger.debug(f"[_has_package_manager]   - Is file, but not executable (isfile={os.path.isfile(full_path)}, access={os.access(full_path, os.X_OK)})")
            else:
                # print(f"[_has_package_manager]   - Is symlink.")
                logger.debug(f"[_has_package_manager]   - Is symlink.")
                try:
                    link_target_name = os.readlink(full_path)
                    # print(f"[_has_package_manager]     - Link target name: {link_target_name}")
                    logger.debug(f"[_has_package_manager]     - Link target name: {link_target_name}")
                    target_path = None
                    if os.path.isabs(link_target_name):
                        target_path = os.path.join(rootfs_path, link_target_name.lstrip('/'))
                    else:
                        symlink_dir = os.path.dirname(full_path)
                        target_path = os.path.normpath(os.path.join(symlink_dir, link_target_name))
                    
                    # print(f"[_has_package_manager]     - Calculated target path: {target_path}")
                    logger.debug(f"[_has_package_manager]     - Calculated target path: {target_path}")
                    if os.path.exists(target_path) and not os.path.isdir(target_path) and os.access(target_path, os.X_OK):
                        # print(f"[_has_package_manager]   - Found symlink pointing to executable target: {pkg_mgr_path} -> {target_path}")
                        logger.debug(f"[_has_package_manager]   - Found symlink pointing to executable target: {pkg_mgr_path} -> {target_path}")
                        return pkg_mgr_path # Return the matched path (the symlink itself)
                    # else:
                        # print(f"[_has_package_manager]     - Target status: Exists={os.path.exists(target_path)}, IsDir={os.path.isdir(target_path)}, Executable={os.access(target_path, os.X_OK)}")
                    logger.debug(f"[_has_package_manager]     - Target status: Exists={os.path.exists(target_path)}, IsDir={os.path.isdir(target_path)}, Executable={os.access(target_path, os.X_OK)}")
                except OSError as e:
                    print(f"[_has_package_manager]     - Error reading link or checking target: {e}")
                    
        # print("[_has_package_manager] No executable package manager found.")
        logger.debug("[_has_package_manager] No executable package manager found.")
        return None # Return None if none found
    
    def _count_files_efficiently(self, rootfs_path):
        """
        Count files more efficiently (limit to max count)
        """
        # Set a reasonable limit - if we exceed this, it's not a minimal image
        MAX_FILES_THRESHOLD = 250 # Increased slightly as 200 might be too low for some "minimal" non-distroless
        count = 0
        
        try:
            for _, _, files in os.walk(rootfs_path):
                count += len(files)
                if count > MAX_FILES_THRESHOLD:
                    # Early return if we exceed threshold
                    return count # Return the count that exceeded, or just MAX_FILES_THRESHOLD + 1
        except OSError as e: # Handle cases where rootfs_path might be problematic after partial extraction
            print(f"OSError during file count: {e}")
            return MAX_FILES_THRESHOLD +1 # Indicate it's likely not minimal
        
        return count
    
    def _get_distribution_info(self, rootfs_path):
        """
        Attempts to read /etc/os-release to determine the Linux distribution.
        Returns a descriptive string (PRETTY_NAME or ID) or None.
        """
        os_release_path = os.path.join(rootfs_path, "etc/os-release")
        # print(f"[_get_distribution_info] Checking path: {os_release_path}")
        logger.debug(f"[_get_distribution_info] Checking path: {os_release_path}")
        distro_info = {}
        try:
            with open(os_release_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        # Remove potential quotes from value
                        value = value.strip('\'"')
                        distro_info[key.upper()] = value 
            
            # Prioritize PRETTY_NAME, then NAME, then ID
            pretty_name = distro_info.get('PRETTY_NAME')
            if pretty_name:
                 # print(f"[_get_distribution_info] Found PRETTY_NAME: {pretty_name}")
                 logger.debug(f"[_get_distribution_info] Found PRETTY_NAME: {pretty_name}")
                 return pretty_name
            
            name = distro_info.get('NAME')
            version = distro_info.get('VERSION_ID')
            if name and version:
                distro_string = f"{name} {version}"
                # print(f"[_get_distribution_info] Found NAME+VERSION_ID: {distro_string}")
                logger.debug(f"[_get_distribution_info] Found NAME+VERSION_ID: {distro_string}")
                return distro_string
            if name:
                 # print(f"[_get_distribution_info] Found NAME: {name}")
                 logger.debug(f"[_get_distribution_info] Found NAME: {name}")
                 return name

            distro_id = distro_info.get('ID')
            if distro_id:
                # print(f"[_get_distribution_info] Found ID: {distro_id}")
                logger.debug(f"[_get_distribution_info] Found ID: {distro_id}")
                return distro_id
            
            # print("[_get_distribution_info] Parsed /etc/os-release but found no suitable identifier.")
            logger.debug("[_get_distribution_info] Parsed /etc/os-release but found no suitable identifier.")
            return None # Found file but no useful ID

        except FileNotFoundError:
            # print("[_get_distribution_info] /etc/os-release not found.")
            # Fallback check for Alpine?
            alpine_release_path = os.path.join(rootfs_path, "etc/alpine-release")
            if os.path.exists(alpine_release_path):
                 # print("[_get_distribution_info] Found /etc/alpine-release.")
                 logger.debug("[_get_distribution_info] Found /etc/alpine-release.")
                 return "Alpine Linux" # Simple identification for Alpine
            return None # File not found
        except Exception as e:
            print(f"[_get_distribution_info] Error reading/parsing /etc/os-release: {e}")
            return None # Error reading file

    def _is_distroless(self, image_name, image_details, rootfs_path, has_shell, has_package_mgr, file_count):
        """
        Determine if an image is distroless based on multiple indicators
        """
        # Fast path: Check image name
        if "distroless" in image_name.lower():
            return True # Strong indicator
        
        # Check image history for distroless references (can be slow, do after name check)
        try:
            history = self.client.api.history(image_name) # image_name can be ID or name:tag
            for layer in history:
                created_by = layer.get("CreatedBy", "")
                # Look for common distroless base image patterns
                if "distroless" in created_by.lower() or "bazel build" in created_by.lower() or "/distroless/" in created_by.lower():
                    return True
        except docker.errors.APIError as e:
            # Ignore history check failures if image not found by name (e.g. only ID was passed)
            print(f"Could not check history for {image_name}: {e}")
            pass 
        except Exception as e_hist: # Catch other potential errors during history check
            print(f"Unexpected error during history check for {image_name}: {e_hist}")
            pass

        # Key characteristics of distroless:
        # 1. No shell
        # 2. No package manager
        # 3. Very few files
        if has_shell or has_package_mgr:
            return False
        
        # File count threshold for distroless is usually very low.
        # Common distroless images (e.g., gcr.io/distroless/static-debian11) have ~20-50 files.
        # Python distroless might have more due to Python stdlib.
        # Let's use a heuristic.
        if file_count < 75:  # Adjusted threshold
            # Further check: absence of common OS indicator files
            # If it's already very minimal and has no shell/pkg_mgr, high chance it's distroless or very close
            missing_os_files = 0
            for os_file in self.os_indicator_files:
                full_path = os.path.join(rootfs_path, os_file)
                if not os.path.exists(full_path):
                    missing_os_files += 1
            
            # If most key OS files are missing, it's a strong sign
            if missing_os_files >= len(self.os_indicator_files) * 0.6: # e.g., 3 out of 5
                return True

        # Fallback: if it doesn't meet the stricter criteria but is still very small and lacks shell/pkg_mgr
        # This is more heuristic.
        # A very low file count (e.g. < 30) on its own with no shell/pkg_mgr is a strong indicator.
        if file_count < 30 and not has_shell and not has_package_mgr:
            return True

        return False 