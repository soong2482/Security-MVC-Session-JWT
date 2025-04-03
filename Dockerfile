# 베이스 이미지 (JDK 17 사용)
FROM openjdk:17-jdk-alpine

# JAR 파일을 컨테이너 내부로 복사
COPY build/libs/*.jar app.jar

# 실행 명령어
ENTRYPOINT ["java", "-jar", "/app.jar"]

# 컨테이너에서 사용할 포트
EXPOSE 8080

