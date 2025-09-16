FROM kalilinux/kali-rolling:latest

# 1. Instala dependencias del sistema
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv sudo git build-essential

# 2. Crea usuario mcpuser con sudo sin password
RUN useradd -m -u 1000 mcpuser && \
    echo 'mcpuser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers && \
    usermod -aG sudo mcpuser

# 3. Prepara el venv global
WORKDIR /app
RUN python3 -m venv /venv
ENV PATH="/venv/bin:$PATH"

# 4. Instala requirements del wrapper MCP
COPY requirements.txt .
RUN /venv/bin/pip install --no-cache-dir -r requirements.txt

# 5. Clona bloodyAD en /tools
WORKDIR /tools
RUN git clone --depth 1 https://github.com/CravateRouge/bloodyAD.git

# 6. Cambia al directorio correcto y ahora SÍ instala los requirements de bloodyAD
WORKDIR /tools/bloodyAD
RUN /venv/bin/pip install --no-cache-dir -r requirements.txt

# 7. Vuelve a /app y copia el wrapper MCP server (ajusta el nombre si es necesario)
WORKDIR /app
COPY bloodyad_assistant_server.py .

# 8. Asegura permisos para mcpuser en todo
RUN chown -R mcpuser:mcpuser /app /tools /venv

# 9. Corre todo como mcpuser (con sudo sin password)
USER mcpuser

# 10. Ejecuta el server Python
CMD ["python", "bloodyad_assistant_server.py"]
