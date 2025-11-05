using System.Security.Cryptography;
using System.Text;

namespace EntropyForge
{
    public partial class MainForm : Form
    {
        // UI controls
        private CheckBox cbLower, cbUpper, cbDigits, cbSymbols, cbAmbiguous;
        private NumericUpDown nudLength;
        private Button btnGenerate, btnClearEntropy, btnCopy;
        private TextBox tbPassword;
        private ProgressBar pbEntropy;
        private Label lblEntropy, lblHint;

        // Entropy pool (internal)
        private byte[] entropyPool; // current SHA256 digest of pool
        private int entropyBitsEstimate; // rough estimate (0..256)
        private object entropyLock = new object(); // lock for thread safety

        // For mouse sampling
        private DateTime lastMouseSample = DateTime.MinValue;
        private const int MouseMinIntervalMs = 5;

        // New: flag indicating whether at least one mouse sample has been collected
        private bool mouseSampleCollected = false;

        // Character sets
        private const string LOWER = "abcdefghijklmnopqrstuvwxyz"; // lowercase
        private const string UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; // uppercase
        private const string DIGITS = "0123456789"; // digits
        private const string SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?"; // symbols
        private const string AMBIGUOUS = "Il1O0"; // ambiguous

        public MainForm()
        {
            // Set up window
            Text = "Password Generator – Mouse Entropy + System RNG";
            Size = new Size(700, 320);
            StartPosition = FormStartPosition.CenterScreen;
            MaximizeBox = false;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;

            InitializeComponents(); // initialize UI
            ResetEntropyPool();     // reset entropy
        }

        private void InitializeComponents()
        {
            // Checkboxes for character options
            cbLower = new CheckBox { Text = "Lowercase (a-z)", Checked = true, Location = new Point(20, 20), AutoSize = true };
            cbUpper = new CheckBox { Text = "Uppercase (A-Z)", Checked = true, Location = new Point(20, 50), AutoSize = true };
            cbDigits = new CheckBox { Text = "Digits (0-9)", Checked = true, Location = new Point(20, 80), AutoSize = true };
            cbSymbols = new CheckBox { Text = "Symbols (!@#...)", Checked = true, Location = new Point(20, 110), AutoSize = true };
            cbAmbiguous = new CheckBox { Text = "Exclude ambiguous (Il1O0)", Checked = true, Location = new Point(20, 140), AutoSize = true };

            // Length label and numeric input
            Label lblLen = new Label { Text = "Password length:", Location = new Point(250, 22), AutoSize = true };
            nudLength = new NumericUpDown { Minimum = 4, Maximum = 256, Value = 16, Location = new Point(350, 18), Width = 70 };

            // Buttons
            btnGenerate = new Button { Text = "Generate", Location = new Point(250, 60), Width = 170 };
            btnGenerate.Click += BtnGenerate_Click;

            // Initially disable generate until user provides mouse entropy
            btnGenerate.Enabled = false;

            btnCopy = new Button { Text = "Copy", Location = new Point(440, 60), Width = 100 };
            btnCopy.Click += BtnCopy_Click;

            btnClearEntropy = new Button { Text = "Reset entropy", Location = new Point(550, 60), Width = 110 };
            btnClearEntropy.Click += (s, e) => { ResetEntropyPool(); UpdateEntropyUI(); };

            // Password textbox
            tbPassword = new TextBox { Location = new Point(250, 100), Width = 410, ReadOnly = true, Font = new Font(FontFamily.GenericMonospace, 10f) };

            // Entropy progress
            lblEntropy = new Label { Text = "Entropy: 0 / 256 bits", Location = new Point(250, 140), AutoSize = true };
            pbEntropy = new ProgressBar { Location = new Point(250, 160), Width = 410, Minimum = 0, Maximum = 256, Value = 0 };

            // Hint
            lblHint = new Label
            {
                Text = "Move your mouse over the form until the bar fills (or enough entropy is gathered), then click \"Generate\".\n(Entropy is mixed with the system cryptographic RNG.)",
                Location = new Point(20, 180),
                Size = new Size(600, 60)
            };

            // Add controls to form
            Controls.AddRange(new Control[]
            {
                cbLower, cbUpper, cbDigits, cbSymbols, cbAmbiguous,
                lblLen, nudLength, btnGenerate, btnCopy, btnClearEntropy,
                tbPassword, lblEntropy, pbEntropy, lblHint
            });

            // Mouse move handler on the whole form
            this.MouseMove += MainForm_MouseMove;
            foreach (Control c in Controls)
                c.MouseMove += MainForm_MouseMove; // also over controls
        }

        private void ResetEntropyPool()
        {
            lock (entropyLock)
            {
                entropyPool = new byte[32]; // 256-bit zeroed digest
                entropyBitsEstimate = 0;    // reset entropy estimate
                mouseSampleCollected = false; // require new mouse movement
            }

            // Disable the generate button until user moves mouse again
            if (InvokeRequired)
            {
                Invoke((Action)(() => btnGenerate.Enabled = false));
            }
            else
            {
                btnGenerate.Enabled = false;
            }
        }

        /// <summary>
        /// Mouse move sampling
        /// Each event: mix (x,y,ticks) into SHA256(pool || data).
        /// Conservative estimate: +1..4 bits per sample (limited to 256 bits)
        /// </summary>
        private void MainForm_MouseMove(object sender, MouseEventArgs e)
        {
            // Throttle sampling
            var now = DateTime.UtcNow;
            if (lastMouseSample != DateTime.MinValue && (now - lastMouseSample).TotalMilliseconds < MouseMinIntervalMs)
                return;
            lastMouseSample = now;

            // Data blob (x,y,ticks)
            long ticks = DateTime.UtcNow.Ticks;
            int x = e.X;
            int y = e.Y;
            long stamp = ticks ^ Environment.TickCount64;

            byte[] data = new byte[24];
            Array.Copy(BitConverter.GetBytes(x), 0, data, 0, 4);
            Array.Copy(BitConverter.GetBytes(y), 0, data, 4, 4);
            Array.Copy(BitConverter.GetBytes(stamp), 0, data, 8, 8);
            Array.Copy(BitConverter.GetBytes(DateTime.Now.Millisecond), 0, data, 16, 4);
            Array.Copy(BitConverter.GetBytes((int)Environment.TickCount), 0, data, 20, 4);

            // Mix into entropyPool via SHA256(pool || data)
            lock (entropyLock)
            {
                using (var sha = SHA256.Create())
                {
                    byte[] concat = new byte[entropyPool.Length + data.Length];
                    Buffer.BlockCopy(entropyPool, 0, concat, 0, entropyPool.Length);
                    Buffer.BlockCopy(data, 0, concat, entropyPool.Length, data.Length);
                    byte[] newPool = sha.ComputeHash(concat);
                    Array.Clear(concat, 0, concat.Length); // clear temporary buffer
                    entropyPool = newPool;
                }

                // Conservative entropy estimate
                entropyBitsEstimate += 2;
                if (entropyBitsEstimate > 256) entropyBitsEstimate = 256;

                // Mark that we have collected at least one mouse sample
                mouseSampleCollected = true;
            }

            // Enable Generate button now that we have at least one mouse sample
            if (InvokeRequired)
            {
                Invoke((Action)(() => btnGenerate.Enabled = true));
            }
            else
            {
                btnGenerate.Enabled = true;
            }

            UpdateEntropyUI();
        }

        private void UpdateEntropyUI()
        {
            if (InvokeRequired)
            {
                Invoke((Action)UpdateEntropyUI); // ensure UI thread
                return;
            }
            lock (entropyLock)
            {
                pbEntropy.Value = entropyBitsEstimate;
                lblEntropy.Text = $"Entropy: {entropyBitsEstimate} / 256 bit";
            }
        }

        private void BtnGenerate_Click(object sender, EventArgs e)
        {
            // Extra guard: do not generate if no mouse entropy was collected
            lock (entropyLock)
            {
                if (!mouseSampleCollected)
                {
                    MessageBox.Show("Please move the mouse over the form to collect entropy before generating a password.", "Not enough entropy", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
            }

            // Build allowed character set
            StringBuilder charSetBuilder = new StringBuilder();
            if (cbLower.Checked) charSetBuilder.Append(LOWER);
            if (cbUpper.Checked) charSetBuilder.Append(UPPER);
            if (cbDigits.Checked) charSetBuilder.Append(DIGITS);
            if (cbSymbols.Checked) charSetBuilder.Append(SYMBOLS);

            string charset = charSetBuilder.ToString();
            if (string.IsNullOrEmpty(charset))
            {
                MessageBox.Show("Please select at least one character set.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (cbAmbiguous.Checked)
            {
                // remove ambiguous characters
                foreach (char c in AMBIGUOUS)
                    charset = charset.Replace(c.ToString(), "");
            }

            int length = (int)nudLength.Value;

            // Mix entropyPool with system RNG bytes
            byte[] systemBytes = new byte[32];
            RandomNumberGenerator.Fill(systemBytes);

            byte[] seed;
            lock (entropyLock)
            {
                using (var sha = SHA256.Create())
                {
                    byte[] concat = new byte[entropyPool.Length + systemBytes.Length];
                    Buffer.BlockCopy(entropyPool, 0, concat, 0, entropyPool.Length);
                    Buffer.BlockCopy(systemBytes, 0, concat, entropyPool.Length, systemBytes.Length);
                    seed = sha.ComputeHash(concat); // final seed
                    Array.Clear(concat, 0, concat.Length);
                }
            }
            Array.Clear(systemBytes, 0, systemBytes.Length);

            // Counter-based SHA256 stream to produce enough random bytes
            int neededBytes = length * 4; // extra margin
            byte[] rndStream = new byte[neededBytes];
            int counter = 0;
            using (var sha = SHA256.Create())
            {
                int pos = 0;
                while (pos < neededBytes)
                {
                    byte[] ctr = BitConverter.GetBytes(counter++);
                    byte[] input = new byte[seed.Length + ctr.Length];
                    Buffer.BlockCopy(seed, 0, input, 0, seed.Length);
                    Buffer.BlockCopy(ctr, 0, input, seed.Length, ctr.Length);
                    byte[] block = sha.ComputeHash(input);
                    int take = Math.Min(block.Length, neededBytes - pos);
                    Buffer.BlockCopy(block, 0, rndStream, pos, take);
                    pos += take;
                    Array.Clear(block, 0, block.Length);
                    Array.Clear(input, 0, input.Length);
                }
            }

            // Convert rndStream into password using unbiased selection
            string password = BuildPasswordFromRandomBytes(rndStream, charset, length);

            // Clear sensitive buffers
            Array.Clear(seed, 0, seed.Length);
            Array.Clear(rndStream, 0, rndStream.Length);

            tbPassword.Text = password;

            // Optionally: increase entropy estimate
            lock (entropyLock)
            {
                entropyBitsEstimate = Math.Min(256, entropyBitsEstimate + 16);
            }
            UpdateEntropyUI();
        }

        private string BuildPasswordFromRandomBytes(byte[] rnd, string charset, int length)
        {
            // Use rejection sampling to avoid modulo bias
            int n = charset.Length;
            StringBuilder sb = new StringBuilder(length);
            int needed = length;
            int pos = 0;
            int available = rnd.Length;

            int maxAccept = (byte.MaxValue / n) * n; // maximum acceptable byte value to avoid bias

            while (needed > 0)
            {
                if (pos >= available)
                    throw new Exception("Not enough random bytes (this shouldn't happen).");

                int v = rnd[pos++] & 0xFF;
                if (v < maxAccept)
                {
                    int idx = v % n;
                    sb.Append(charset[idx]);
                    needed--;
                }
            }
            return sb.ToString();
        }

        private void BtnCopy_Click(object sender, EventArgs e)
        {
            if (!string.IsNullOrEmpty(tbPassword.Text))
            {
                Clipboard.SetText(tbPassword.Text);
                MessageBox.Show("The password has been copied to the clipboard.", "Ready", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        // Clean up sensitive buffers on close
        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            lock (entropyLock)
            {
                if (entropyPool != null) Array.Clear(entropyPool, 0, entropyPool.Length);
                entropyBitsEstimate = 0;
                mouseSampleCollected = false;
            }
            base.OnFormClosing(e);
        }
    }
}