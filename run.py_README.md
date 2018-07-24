# Build the container

docker build -t vautomator .

# Run the run.py file inside the container

docker run -v ${PWD}/results:/app/results -it vautomator:latest python /app/run.py INSERT_FQDN

Example:
docker run -v ${PWD}/results:/app/results -it vautomator:latest python /app/run.py blog.rubidus.com