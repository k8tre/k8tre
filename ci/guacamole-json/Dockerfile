FROM docker.io/guacamole/guacamole:1.6.0

USER root

# Create config directory and copy JSON extension JAR to the correct location
RUN mkdir -p /etc/guacamole/extensions && \
    cp /opt/guacamole/extensions/guacamole-auth-json/guacamole-auth-json.jar /etc/guacamole/extensions/ && \
    chown -R guacamole:guacamole /etc/guacamole

# Remove unwanted environment directories to disable other extensions  
RUN rm -rf /opt/guacamole/environment/BAN_* \
        /opt/guacamole/environment/HEADER_* \
        /opt/guacamole/environment/LDAP_* \
        /opt/guacamole/environment/JDBC_* \
        /opt/guacamole/environment/SSO_* \
        /opt/guacamole/environment/VAULT_* 2>/dev/null || true

# Verify the setup - JAR should be directly in /etc/guacamole/extensions/
RUN echo "Extensions in /etc/guacamole/extensions/:" && \
    ls -la /etc/guacamole/extensions/

USER guacamole