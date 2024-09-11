import morgan, { StreamOptions } from 'morgan';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const colorReset = '\x1b[0m';
const colorGreen = '\x1b[32m';
const colorYellow = '\x1b[33m';
const colorRed = '\x1b[31m';


const customMorganFormat: morgan.FormatFn = (tokens, req, res) => {
  const status = tokens.status(req, res);
  const statusColor =
    status && parseInt(status, 10) >= 500
      ? colorRed
      : status && parseInt(status, 10) >= 400
      ? colorYellow
      : colorGreen;

  return [
    statusColor,
    tokens.method(req, res),
    tokens.url(req, res),
    status,
    tokens['response-time'](req, res) + ' ms',
    tokens.date(req, res, 'web'),
    colorReset,
  ].join(' ');
};


const accessLogStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' });

const stream: StreamOptions = {
  write: (message) => accessLogStream.write(message),
};

export const loggerMiddleware = [
  morgan(customMorganFormat), // Custom format with colors for console
  morgan(':method :url :status :response-time ms :date[web]', { stream }), // Logs to file without colors
];


// import morgan from 'morgan';
// import fs from 'fs';
// import path from 'path';
// import { fileURLToPath } from 'url';

// const __filename = fileURLToPath(import.meta.url);
// const __dirname = path.dirname(__filename);

// const morganFormat = ':method :url :status :response-time ms :date[web]';
// const accessLogStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' });

// export const loggerMiddleware = [
//     morgan(morganFormat),
//     morgan(morganFormat, { stream: accessLogStream })
// ];

