using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

internal static class DefenderWorkloadHelper
{
    private static int Main(string[] args)
    {
        try
        {
            var options = ParseArgs(args);
            var objDir = GetRequired(options, "--objDir");
            var cacheDir = GetRequired(options, "--cacheDir");
            var tag = options.ContainsKey("--tag") ? options["--tag"] : DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            var repeat = options.ContainsKey("--repeat") ? Math.Max(1, int.Parse(options["--repeat"])) : 6;

            Directory.CreateDirectory(objDir);
            Directory.CreateDirectory(cacheDir);

            for (var i = 0; i < repeat; i++)
            {
                var pdbPath = Path.Combine(objDir, string.Format("symbols_{0}_{1:D2}.pdb", tag, i));
                var dllPath = Path.Combine(objDir, string.Format("module_{0}_{1:D2}.dll", tag, i));
                var jsonPath = Path.Combine(cacheDir, string.Format("restore_{0}_{1:D2}.json", tag, i));
                var cachePath = Path.Combine(cacheDir, string.Format("artifact_{0}_{1:D2}.cache", tag, i));

                WriteText(pdbPath, BuildPdbPayload(tag, i));
                WriteText(jsonPath, BuildJsonPayload(tag, i));
                WriteText(cachePath, BuildCachePayload(tag, i));
                WriteBinary(dllPath, 4096, (byte)(65 + (i % 20)));

                AppendText(pdbPath, Environment.NewLine + "# touch " + DateTime.Now.ToString("HH:mm:ss.fff"));
                AppendText(jsonPath, Environment.NewLine + "{\"status\":\"updated\",\"iteration\":" + i + "}");
                ReadChunk(pdbPath);
                ReadChunk(jsonPath);
                ReadChunk(cachePath);
                ReadChunk(dllPath);

                Thread.Sleep(25);
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    private static Dictionary<string, string> ParseArgs(string[] args)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < args.Length; i++)
        {
            var key = args[i];
            if (!key.StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            if (i + 1 >= args.Length)
            {
                map[key] = string.Empty;
                continue;
            }

            map[key] = args[i + 1];
            i++;
        }

        return map;
    }

    private static string GetRequired(Dictionary<string, string> options, string key)
    {
        string value;
        if (!options.TryGetValue(key, out value) || string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Missing required argument: " + key);
        }

        return value;
    }

    private static string BuildPdbPayload(string tag, int iteration)
    {
        var builder = new StringBuilder();
        builder.AppendLine("Microsoft C/C++ MSF 7.00");
        builder.AppendLine("PDB helper payload");
        builder.AppendLine("Tag=" + tag);
        builder.AppendLine("Iteration=" + iteration);
        builder.AppendLine("Timestamp=" + DateTime.UtcNow.ToString("o"));
        builder.Append('x', 2048);
        return builder.ToString();
    }

    private static string BuildJsonPayload(string tag, int iteration)
    {
        return "{\"tag\":\"" + tag + "\",\"iteration\":" + iteration + ",\"kind\":\"restore\",\"timestamp\":\"" + DateTime.UtcNow.ToString("o") + "\"}";
    }

    private static string BuildCachePayload(string tag, int iteration)
    {
        var builder = new StringBuilder();
        builder.AppendLine("cache-entry");
        builder.AppendLine("tag=" + tag);
        builder.AppendLine("iteration=" + iteration);
        builder.Append('c', 3072);
        return builder.ToString();
    }

    private static void WriteText(string path, string content)
    {
        File.WriteAllText(path, content, Encoding.UTF8);
    }

    private static void AppendText(string path, string content)
    {
        File.AppendAllText(path, content, Encoding.UTF8);
    }

    private static void WriteBinary(string path, int length, byte seed)
    {
        var bytes = new byte[length];
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)(seed + (i % 7));
        }
        File.WriteAllBytes(path, bytes);
    }

    private static void ReadChunk(string path)
    {
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            var buffer = new byte[2048];
            stream.Read(buffer, 0, buffer.Length);
        }
    }
}
