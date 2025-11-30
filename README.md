# Cliqtrix-26-Backend

A Node.js backend service for POSH (Prevention of Sexual Harassment) detection and website safety checking.

## Features

- POSH detection using AI/ML models
- Website safety analysis with VirusTotal integration
- RESTful API endpoints
- Express.js server

## Installation

```bash
npm install
```

## Environment Variables

Create a `.env` file with the following variables:

```
BOT_API_KEY=your_bot_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
GROQ_API_KEY=your_groq_api_key
PORT=3000
```

## Usage

### Development
```bash
npm run dev
```

### Production
```bash
npm start
```

## API Endpoints

- `POST /posh-detect` - Detect POSH violations in text
- `POST /check-website-safety` - Check website safety status

## Deployment

This project is configured for deployment on Vercel.