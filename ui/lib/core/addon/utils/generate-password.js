import { generatePassword as libGenPW } from 'secure-password-utilities';
import { DIGIT_CHARSET, LOWERCASE_CHARSET, UPPERCASE_CHARSET } from 'secure-password-utilities/constants';

// Define sets of allowed characters
export const CHARACTER_TYPES = {
  lower: LOWERCASE_CHARSET,
  upper: UPPERCASE_CHARSET,
  digits: DIGIT_CHARSET,
  symbols: '!@#$%^&*()_+~',
};

// Library's option names
const LIBRARY_OPTION = { lower: 'lowercase', upper: 'uppercase', digits: 'digits', symbols: 'symbols' };

// Same lengths as server-side default generator
export const DEFAULT_LENGTH = 20;
export const MIN_LENGTH = 8;
export const MAX_LENGTH = 128;

// Generates a random password in the broswer using `secure-password-utilities`
export default function generatePassword({
  length = DEFAULT_LENGTH,
  lower = true,
  upper = true,
  digits = true,
  symbols = true,
} = {}) {
  const types = { lower, upper, digits, symbols };
  const selected = Object.keys(CHARACTER_TYPES).filter((key) => types[key]);

  // Return error messages for modal
  if (selected.length === 0) {
    throw new Error('Select at least one character types');
  }
  if (!Number.isInteger(length) || length < MIN_LENGTH || length > MAX_LENGTH) {
    throw new Error(`Length must be an integer from ${MIN_LENGTH} to ${MAX_LENGTH}`);
  }

  const options = { charset: {} };
  Object.entries(CHARACTER_TYPES).forEach(([key, chars]) => {
    options[LIBRARY_OPTION[key]] = selected.includes(key) ? { min: 1 } : false;
    options.charset[LIBRARY_OPTION[key]] = chars;
  });

  return libGenPW(length, options);
}
