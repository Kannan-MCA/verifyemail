
# 🚀 Spring Boot Application - Docker Deployment Guide

This guide helps you build and run your Spring Boot application inside a Docker container, using environment variables and MySQL integration.

---

## 🛠️ Prerequisites

Ensure the following are installed and configured:

- ✅ Docker
- ✅ MySQL (locally or in a container)
- ✅ Java 17+ (for local builds)

mvn clean package
docker build -t my-springboot-app .

docker run -d \
  --name springboot-app \
  -p 8080:8080 \
  -e DB_HOST=your-mysql-host \
  -e DB_PORT=3306 \
  -e DB_NAME=your-database-name \
  -e DB_USER=your-db-user \
  -e DB_PASS=your-db-password \
  -e DISPOSABLE_DOMAINS= dominOne,domainTwo
  my-springboot-app
