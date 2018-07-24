# Build the container

docker build -t vautomator .

# Run the run.py file inside the container and look at results in ./results folder in source repo

docker run -v ${PWD}/results:/app/results -it vautomator:latest python /app/run.py INSERT_FQDN

Example:
docker run -v ${PWD}/results:/app/results -it vautomator:latest python /app/run.py blog.rubidus.com

# Upload results to GDrive/BMO/S3 Bucket/ZIP/or whatever

TBD