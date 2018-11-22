using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace DLLInjector3
{
    public partial class Form1 : Form
    {

        private string targetProcessName;
        private System.Diagnostics.Process[] targetProcesses;
        private IntPtr targetProcessHandle, kernel32Handle, dllpathRemoteAddr, loadLibraryAddr;

        public Form1()
        {
            InitializeComponent();
            listBox1.Items.Clear();
            updateProcessList();
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        // 「インジェクトするDLL」ボタンクリック時の処理
        private void button1_Click(object sender, EventArgs e)
        {
            openFileDialog1.Filter = "DLLファイル(*.dll)|*.dll";
            // ファイル選択ダイアログ表示
            if (openFileDialog1.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                textBox1.Text = openFileDialog1.FileName;
            }
        }

        // 「インジェクト」ボタンクリック時の処理
        private void button2_Click(object sender, EventArgs e)
        {
            if (listBox1.SelectedIndex < 0)
            {
                MessageBox.Show("プロセスを選択してください");
                return;
            }
            if (textBox1.Text == "")
            {
                MessageBox.Show("インジェクトするDLLを選択してください");
                return;
            }
            targetProcessName = listBox1.SelectedItem.ToString();
            targetProcesses = System.Diagnostics.Process.GetProcessesByName(targetProcessName);

            MessageBox.Show("targetProcessName = " + targetProcessName);


            MessageBox.Show("PID = " + targetProcesses[0].Id.ToString());
            targetProcessHandle = OpenProcess(DesiredAccess.PROCESS_ALL_ACCESS/*DesiredAccess.PROCESS_CREATE_THREAD | DesiredAccess.PROCESS_QUERY_INFORMATION | DesiredAccess.PROCESS_VM_OPERATION | DesiredAccess.PROCESS_VM_WRITE*/, false, (uint)targetProcesses[0].Id);
            if (targetProcessHandle == (IntPtr)null)
            {
                MessageBox.Show("OpenProcess() failed");
                return;
            }

            MessageBox.Show("targetProcessHandle = " + targetProcessHandle.ToString());

            String dllpath = textBox1.Text;
            uint dllpathLength = (uint)Encoding.GetEncoding("UTF-8").GetByteCount(dllpath);
            dllpathRemoteAddr = VirtualAllocEx(targetProcessHandle, (IntPtr)null, dllpathLength + 1, AllocationType.MEM_COMMIT, MemoryProtection.PAGE_EXECUTE_READWRITE);
            if (dllpathRemoteAddr == (IntPtr)null)
            {
                MessageBox.Show("VirtualAllocEx() failed()");
                CloseHandle(targetProcessHandle);
                return;
            }
            MessageBox.Show("remoteDllpathAddr = " + dllpathRemoteAddr.ToString());

            WriteProcessMemory(targetProcessHandle, dllpathRemoteAddr, dllpath, dllpathLength + 1, (IntPtr)null);

            kernel32Handle = LoadLibrary("kernel32.dll");
            loadLibraryAddr = GetProcAddress(kernel32Handle, "LoadLibraryA");
            if (loadLibraryAddr == (IntPtr)null)
            {
                MessageBox.Show("GetProcAddress() failed()");
                CloseHandle(targetProcessHandle);
                return;
            }
            MessageBox.Show("loadLibraryAddr = " + loadLibraryAddr.ToString());

            IntPtr retval;
            retval = CreateRemoteThread(targetProcessHandle, (IntPtr)null, 0, loadLibraryAddr, dllpathRemoteAddr, 0, (IntPtr)null);
            if (retval == (IntPtr)null)
            {
                MessageBox.Show("CreateRemoteThread() failed");
                VirtualFreeEx(targetProcessHandle, dllpathRemoteAddr, (uint)(dllpath.Length + 1), FreeType.MEM_RELEASE);
                CloseHandle(targetProcessHandle);
                return;
            }

            MessageBox.Show("CreateRemoteThread retval = " + retval.ToString());

            VirtualFreeEx(targetProcessHandle, dllpathRemoteAddr, (uint)(dllpath.Length + 1), FreeType.MEM_RELEASE);
            CloseHandle(targetProcessHandle);
        }

        // 「プロセス一覧更新」ボタンクリック時の処理
        private void button3_Click(object sender, EventArgs e)
        {
            updateProcessList();
        }

        // プロセス一覧をリストボックスに表示する。
        private void updateProcessList()
        {
            Process[] processes = Process.GetProcesses();
            listBox1.Items.Clear();
            foreach (Process ps in processes)
            {
                listBox1.Items.Add(ps.ProcessName.ToString());
            }
        }

        [Flags]
        enum AllocationType
        {
            MEM_COMMIT = 0x1000,
            MEM_RESERVE = 0x2000,
        }

        [Flags]
        enum MemoryProtection
        {
            PAGE_EXECUTE_READWRITE = 0x40,
        }

        [Flags]
        enum FreeType
        {
            MEM_RELEASE = 0x8000,
        }

        [Flags]
        enum DesiredAccess
        {
            PROCESS_ALL_ACCESS = 0x1fffff,
            PROCESS_QUERY_INFORMATION = 0x400,
            PROCESS_CREATE_THREAD = 0x2,
            PROCESS_VM_OPERATION = 0x8,
            PROCESS_VM_WRITE = 0x20,
        }

        // Win32APIをインポート
        [DllImport("Kernel32.dll")]
        extern static IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("Kernel32.dll")]
        extern static bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, FreeType dwFreeType);

        [DllImport("Kernel32.dll")]
        extern static IntPtr OpenProcess(DesiredAccess dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("Kernel32.dll")]
        extern static bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        extern static bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, String lpBuffer, uint nSize, IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        extern static IntPtr LoadLibrary(String lpFileName);

        [DllImport("kernel32.dll")]
        extern static IntPtr GetProcAddress(IntPtr hModule, String lpProcName);

        [DllImport("kernel32.dll")]
        extern static IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    }
}
