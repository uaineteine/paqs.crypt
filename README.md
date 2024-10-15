# paqs.crypt v1.0

A .NET library provides functionalities to encrypt byte data.

## Example Usage
```csharp
Console.WriteLine("Hello, World!");
string password = "your_password";
// Generate a random initialization vector (IV)
byte[] iv = AesEncryption.GenerateRandomIV();
byte[] data = Encoding.UTF8.GetBytes("Hello, World!");

// Encrypt the data
byte[] encryptedData = AesEncryption.EncryptWithSha256Salt(data, password, iv);
Console.WriteLine("Encrypted Data: " + Convert.ToBase64String(encryptedData));

// Decrypt the data
byte[] decryptedData = AesEncryption.DecryptWithSha256Salt(encryptedData, password, iv);
Console.WriteLine("Decrypted Data: " + Encoding.UTF8.GetString(decryptedData));
```

## Contributing
We welcome contributions! Please submit a pull request or open an issue if you have any suggestions or find any bugs.

## License
paqs.crypt is licensed under the GNU License.

## Author
Daniel Stamer-Squair 2024
