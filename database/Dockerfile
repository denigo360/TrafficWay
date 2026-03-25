FROM postgres:15-alpine

COPY ./init /docker-entrypoint-initdb.d/

RUN chmod -R 755 /docker-entrypoint-initdb.d/
