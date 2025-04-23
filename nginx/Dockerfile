FROM alpine:3.21

RUN apk add --no-cache nginx 
    
RUN mkdir -p /run/nginx && \
    mkdir -p /var/log/nginx && \
    mkdir -p /var/lib/nginx

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

RUN chown -R appuser:appgroup /var/lib/nginx /var/log/nginx /run/nginx

EXPOSE 80

USER appuser

ENTRYPOINT ["nginx", "-g", "daemon off;"]