version: '3.9'

services:
  app:
    build: .
    container_name: smartest-bug-hunter
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=sqlite:///./smartest_bug_hunter.db
      - SECRET_KEY=change-me-please-super-secret-key
    volumes:
      - .:/app
