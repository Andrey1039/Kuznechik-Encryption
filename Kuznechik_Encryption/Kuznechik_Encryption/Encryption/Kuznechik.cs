using System.Linq;
using System.Text;
using Kuznechik_Encryption.Data;
using System.Collections.Generic;

namespace Kuznechik_Encryption.Encryption
{
    internal class Kuznechik
    {
        // Умножение чисел в поле Галуа
        private byte GF_Mul(byte a, byte b)
        {
            byte p = 0;

            for (byte counter = 0; counter < 8 && a != 0 && b != 0; counter++)
            {
                if ((b & 1) != 0)
                    p ^= a;

                byte hi_bit_set = (byte)(a & 0x80);
                a = (byte)((a << 1) & 0xff);

                if (hi_bit_set != 0)
                    a ^= 0xc3;
                b >>= 1;
            }

            return p;
        }

        // Сдвиг данных и реализация уравнения для L (прямая)
        private byte[] R(byte[] data)
        {
            byte a = 0;

            for (int i = 0; i < 16; i++)
                a ^= GF_Mul(data[i], ConversionTables.L_Mass[i]);

            for (int i = 15; i >= 0; i--)
                if (i != 0)
                    data[i] = data[i - 1];
                else
                    data[i] = a;

            return data;
        }

        // Сдвиг данных и реализация уравнения для L (обратная)
        private byte[] R_Reverse(byte[] data)
        {
            byte a = data[0];
            byte[] newData = new byte[16];

            for (int i = 0; i < 15; i++)
                newData[i] = data[i + 1];

            for (int i = 15; i >= 0; i--)
                a ^= GF_Mul(newData[i], ConversionTables.L_Mass[i]);

            newData[15] = a;

            return newData;
        }

        // Побитовый XOR ключа и входного блока данных
        private byte[] X(byte[] a, byte[] b)
        {
            byte[] output = new byte[16];

            for (int i = 0; i < 16; i++)
                output[i] = (byte)(a[i] ^ b[i]);

            return output;
        }

        // Нелинейное преобразование
        private byte[] S(byte[] data, bool encryption)
        {
            byte[] output = new byte[16];

            for (int i = 0; i < data.Length; i++)
                if (encryption)
                    output[i] = ConversionTables.Pi[data[i]];
                else
                    output[i] = ConversionTables.Pi_Reverse[data[i]];

            return output;
        }

        // Линейное преобразование
        private byte[] L(byte[] data, bool encryption)
        {
            for (int i = 0; i < 16; i++)
                if (encryption)
                    data = R(data);
                else
                    data = R_Reverse(data);

            return data;
        }

        // Преобразование данных (шифрование)
        private string XSL(byte[] partsData, List<byte[]> partsKey)
        {
            byte[] codedData = new byte[16];

            for (int j = 0; j <= 8; j++)
            {
                codedData = X(partsKey[j], partsData);
                codedData = S(codedData, true);
                codedData = L(codedData, true);

                partsData = codedData;
            }

            codedData = X(partsKey[9], codedData);
            string result = Encoding.GetEncoding(1251).GetString(codedData);

            return result;
        }

        // Преобразование данных (расшифрование)
        private string LSX(byte[] partsData, List<byte[]> partsKey)
        {
            byte[] codedData = X(partsKey[9], partsData);

            for (int j = 8; j >= 0; j--)
            {
                codedData = L(codedData, false);
                codedData = S(codedData, false);
                codedData = X(partsKey[j], codedData);
            }

            string result = Encoding.GetEncoding(1251).GetString(codedData);

            return result;
        }

        // Вычисление констант
        private List<byte[]> C_Calculate()
        {
            List<byte[]> c = new List<byte[]>();

            for (int i = 0; i < 32; i++)
            {
                c.Add(new byte[16]);
                c[i][15] = (byte)(i + 1);
                c[i] = L(c[i], true);
            }

            return c;
        }

        // Сеть Фейстеля
        private List<byte[]> Feistel(byte[] keyA, byte[] keyB, byte[] c)
        {
            List<byte[]> keys = new List<byte[]>
            {
                X(L(S(X(keyA, c), true), true), keyB), 
                keyA
            };

            return keys;
        }

        // Формирование списка ключей
        private List<byte[]> GetKeys(string key)
        {
            List<byte[]> keys = new List<byte[]>();
            List<byte[]> tempKeyA = new List<byte[]>();

            List<byte[]> c = C_Calculate();

            keys.Add(Encoding.GetEncoding(1251).GetBytes(key.Substring(0, key.Length / 2)));
            keys.Add(Encoding.GetEncoding(1251).GetBytes(key.Substring(key.Length / 2, key.Length / 2)));

            tempKeyA.Add(keys[0]);
            tempKeyA.Add(keys[1]);

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 8; j += 2)
                {
                    List<byte[]> tempKeyB = Feistel(tempKeyA[0], tempKeyA[1], c[8 * i + j]);
                    tempKeyA = Feistel(tempKeyB[0], tempKeyB[1], c[8 * i + j + 1]);
                }

                keys.Add(tempKeyA[0]);
                keys.Add(tempKeyA[1]);
            }

            return keys;
        }

        // Формирование списка сообщений
        private List<byte[]> GetMessage(string data)
        {
            while (data.Length % 16 != 0)
                data += "\0";

            byte[] byteText = Encoding.GetEncoding(1251).GetBytes(data);

            int counter = 16;
            List<byte[]> result = byteText.GroupBy(_ => counter++ / 16).Select(v => v.ToArray()).ToList();

            return result;
        }

        // Шифрование сообщения
        public string Encryption(string data, string key)
        {
            string result = string.Empty;
            
            List<byte[]> partsKey = GetKeys(key);
            List<byte[]> partsData = GetMessage(data);

            for (int i = 0; i < partsData.Count; i++)
                result += XSL(partsData[i], partsKey);

            return result;
        }

        // Дешифрование сообщения
        public string Decryption(string data, string key)
        {
            string result = string.Empty;
            
            List<byte[]> partsKey = GetKeys(key);
            List<byte[]> partsData = GetMessage(data);

            for (int i = 0; i < partsData.Count; i++)
                result += LSX(partsData[i], partsKey);

            return result;
        }
    }
}
