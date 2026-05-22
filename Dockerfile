# -------- Stage 1: Build --------
FROM maven:3.9.9-eclipse-temurin-21 AS builder

WORKDIR /build

# Copy pom.xml and download dependencies
COPY pom.xml .
RUN mvn -B dependency:go-offline -DskipTests

# Copy source and build
COPY src ./src
RUN mvn clean package -DskipTests

# -------- Stage 2: Runtime --------
FROM eclipse-temurin:21-jdk-jammy

WORKDIR /app

# Create spring user
RUN addgroup --system spring && adduser --system spring --ingroup spring

# Copy JAR
COPY --from=builder /build/target/*.jar app.jar

# Create logs directory
RUN mkdir -p /app/logs && chown spring:spring /app/logs

# Switch to spring user
USER spring

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java","-XX:+UseContainerSupport","-Xmx512m","-Xms256m","-jar","app.jar"]