# ================================
#  Detectify v4 — Dockerfile
# ================================

FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package files first (cache layer)
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production

# Copy rest of app
COPY . .

# Create logs directory
RUN mkdir -p logs

# Don't run as root
RUN addgroup -S detectify && adduser -S detectify -G detectify
RUN chown -R detectify:detectify /app
USER detectify

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/api/health', r => process.exit(r.statusCode === 200 ? 0 : 1))"

# Start
CMD ["node", "server/index.js"]
