import docker
from models.schemas import DockerContainerInfo, DockerImageInfo # Updated imports
from sqlalchemy.orm import Session # Added for type hinting if db session is used
from datetime import datetime # For parsing timestamp
import dateutil.parser # For robust ISO 8601 parsing

# The spec's list_containers in main.py passes `db` to get_running_containers.
# The get_running_containers in the spec (section 7.2) does not accept `db`.
# I will add `db: Session` to the signature here, but it won't be used yet, 
# anticipating it might be needed for fetching scan data later.
def get_running_containers(db: Session = None) -> list[DockerContainerInfo]: # Updated return type hint
    client = docker.from_env()
    try:
        raw_containers = client.containers.list()
    except docker.errors.DockerException as e:
        print(f"Error connecting to Docker: {e}")
        # Potentially return an empty list or raise a custom exception
        return []
    
    container_info_list = []
    for container in raw_containers:
        try:
            image_obj = container.image
            image_tags = image_obj.tags
            primary_image_name_tag = image_tags[0] if image_tags else (image_obj.short_id or image_obj.id)
            
            container_created_at_str = container.attrs.get('Created')
            container_created_at_dt = dateutil.parser.isoparse(container_created_at_str) if container_created_at_str else datetime.utcnow()

            image_created_at_dt = None
            if image_obj.attrs.get('Created'):
                image_created_at_dt = dateutil.parser.isoparse(image_obj.attrs['Created'])
            
            image_details_data = DockerImageInfo(
                id=image_obj.id, # Full SHA ID
                short_id=image_obj.short_id.replace("sha256:", "")[:12] if image_obj.short_id else image_obj.id.replace("sha256:", "")[:12],
                tags=image_tags if image_tags else [],
                size=image_obj.attrs.get('Size'),
                created_at=image_created_at_dt
            )

            container_data = DockerContainerInfo(
                id=container.short_id,
                name=container.name,
                image_id=image_details_data.short_id, # Use the parsed short_id from image_details
                image_name=primary_image_name_tag,
                status=container.status,
                created_at=container_created_at_dt,
                image_details=image_details_data
            )
            container_info_list.append(container_data)
        except Exception as e:
            # Log error for specific container and continue if possible
            print(f"Error processing container {container.id}: {e}")
            # Optionally, add a placeholder or skip this container
            continue
            
    return container_info_list 