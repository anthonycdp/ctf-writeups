FROM python:3.9-slim

WORKDIR /app

# Install dependencies
RUN pip install flask

# Copy challenge files
COPY challenge.py /app/challenge.py

# Expose port
EXPOSE 5000

# Run the challenge
CMD ["python", "challenge.py"]
