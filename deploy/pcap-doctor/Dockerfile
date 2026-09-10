FROM python:3.13-alpine

RUN addgroup -S -g 10001 pcapdoctor && adduser -S -D -H -u 10001 -G pcapdoctor pcapdoctor
WORKDIR /app
COPY web/ /app/
USER 10001:10001
EXPOSE 8080
CMD ["python", "-m", "http.server", "8080", "--directory", "/app"]
