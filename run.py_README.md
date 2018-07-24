# Build the container

docker build -t vautomator .

# Run the run.py file inside the container and look at results in ./results folder in source repo

docker run -v ${PWD}/results:/app/results -it vautomator:latest python /app/run.py INSERT_FQDN

Example:
docker run -v ${PWD}/results:/app/results -it vautomator:latest python /app/run.py blog.rubidus.com

# Upload results to GDrive/BMO/S3 Bucket/ZIP/or whatever

results will be posted into ./results/INSERT_FQDN_NAME/...

A tar.gz is also available in ./results/INSERT_FQDN_NAME.tar.gz for uploading to a bug for record keeping