using paqs.crypt;
using System.Text;

internal class Program
{
    private static void Main(string[] args)
    {
        Console.WriteLine("Hello, World!");

        string password = "your_password";
        //byte[] salt = Encoding.UTF8.GetBytes("your_salt");
        byte[] iv = AesEncryption.GenerateRandomIV();
        byte[] data = Encoding.UTF8.GetBytes("Hello, World!");

        // Encrypt the data
        byte[] encryptedData = AesEncryption.EncryptWithSha256Salt(data, password, iv);
        Console.WriteLine("Encrypted Data: " + Convert.ToBase64String(encryptedData));

        // Decrypt the data
        byte[] decryptedData = AesEncryption.DecryptWithSha256Salt(encryptedData, password, iv);
        Console.WriteLine("Decrypted Data: " + Encoding.UTF8.GetString(decryptedData));
    }
}