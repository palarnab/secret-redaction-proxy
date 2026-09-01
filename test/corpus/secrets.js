'use strict';

/**
 * Fake-but-realistic secrets for detector/roundtrip testing. None of these are
 * real credentials — they mirror the *shape* of real ones so detectors can be
 * exercised without exposing anything sensitive.
 */
module.exports = {
  positives: [
    { type: 'aws-access-key-id', text: 'AKIAIOSFODNN7EXAMPLE' },
    {
      type: 'aws-secret-access-key',
      text: 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    },
    {
      type: 'github-pat',
      text: 'token ghp_1234567890abcdefghijklmnopqrstuvwxyz',
    },
    {
      type: 'openai-key',
      text: 'OPENAI_API_KEY=sk-abcdef12345ABCDEF67890ghijklMNOPqrstUVWX',
    },
    {
      type: 'anthropic-key',
      text: 'ANTHROPIC_API_KEY=sk-ant-api03-abcDEF123456ghiJKL789mnoPQR',
    },
    {
      type: 'stripe-secret-key',
      text: 'STRIPE=sk_live_abcdefghijklmnop12345678',
    },
    {
      type: 'google-api-key',
      text: 'AIzaSyA1234567890abcdefghijklmnopqrstuv',
    },
    {
      type: 'mongodb-uri',
      text: 'mongodb+srv://admin:S3cr3tPass@cluster0.ab12.mongodb.net/prod',
    },
    {
      type: 'connection-string',
      text: 'postgres://dbuser:hunter2pw@db.internal.example.com:5432/app',
    },
    {
      type: 'url-with-credentials',
      text: 'https://svcacct:tok3nValue@api.example.com/v1/things',
    },
    {
      type: 'jwt',
      text:
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
        '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0' +
        '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    },
    {
      type: 'private-key-pem',
      text:
        '-----BEGIN RSA PRIVATE KEY-----\n' +
        'MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n' +
        'KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIL0e\n' +
        '-----END RSA PRIVATE KEY-----',
    },
  ],

  // Strings that should NOT trip high-confidence (fail-closed) detectors.
  negatives: [
    'The quick brown fox jumps over the lazy dog.',
    'commit 9f8e7d6c5b4a3210fedcba9876543210deadbeef',
    'version 1.2.3-beta build 20260901',
    'https://example.com/docs/getting-started?utm=1',
  ],
};
