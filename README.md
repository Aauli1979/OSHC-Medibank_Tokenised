To allocate a port to run the web-app backend 
Backend  netstat -ano | findstr :8080  tasklist /FI "PID eq 8840"  taskkill /PID 8840 /F  mvn spring-boot:run (for the 1st time)
mvn spring-boot:run (after the 1st time)

Frontend  npm install   npm run dev (if the frontend has error, run npm clean package before npm install)
