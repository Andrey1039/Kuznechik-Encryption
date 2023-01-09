using System.Text;
using System.Windows;
using System.Windows.Controls;
using Kuznechik_Encryption.Encryption;

namespace Kuznechik_Encryption
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            InstallParams();
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        }

        private void InstallParams()
        {
            InputTextTB.Text = "qwertyuiopasdfgh";
            InputKeyTB.Text = "123456789ghtrewsdcvbnmkjhgfdsazx";
        }

        private void InputData_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (InputTextTB.Text.Equals(string.Empty) || InputKeyTB.Text.Length != 32)
                ExecuteBtn.IsEnabled = false;
            else
                ExecuteBtn.IsEnabled = true;
        }

        private void ExecuteBtn_Click(object sender, RoutedEventArgs e)
        {
            Kuznechik message = new Kuznechik();
            string text = message.Encryption(InputTextTB.Text, InputKeyTB.Text);
            EncryptMessTB.Text = text;
            DecryptMessTB.Text = message.Decryption(text, InputKeyTB.Text);
        }        
    }
}
