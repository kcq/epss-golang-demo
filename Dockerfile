#intentionally older Ubuntu version (hopefully we'll get a few vulnerabilities with it :-))
FROM ubuntu:18.04

WORKDIR /app
COPY ./app /app/
ENTRYPOINT ["./app"]
