FROM kalilinux/kali-rolling:latest

# 1. Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv sudo git build-essential

# 2. Create mcpuser with passwordless sudo
RUN useradd -m -u 1000 mcpuser && \
    echo 'mcpuser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers && \
    usermod -aG sudo mcpuser

# 3. Prepare the global venv
WORKDIR /app
RUN python3 -m venv /venv
ENV PATH="/venv/bin:$PATH"

# 4. Install MCP wrapper requirements
COPY requirements.txt .
RUN /venv/bin/pip install --no-cache-dir -r requirements.txt

# 5. Clone bloodyAD into /tools
WORKDIR /tools
RUN git clone --depth 1 https://github.com/CravateRouge/bloodyAD.git

# 6. Change to the correct directory and NOW install bloodyAD's requirements
WORKDIR /tools/bloodyAD
RUN /venv/bin/pip install --no-cache-dir -r requirements.txt

# 7. Return to /app and copy the MCP server wrapper (adjust the name if necessary)
WORKDIR /app
COPY bloodyad_mcp_server.py .

# 8. Ensure mcpuser has permissions on everything
RUN chown -R mcpuser:mcpuser /app /tools /venv

# 9. Run everything as mcpuser (with passwordless sudo)
USER mcpuser

# 10. Execute the Python server
CMD ["python", "bloodyad_mcp_server.py"]