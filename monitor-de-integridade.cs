using System.Security.Cryptography;
using System.Text.Json;

namespace MegaBrainSentinel;

public sealed class IntegrityMonitor : IDisposable
{
    private readonly string _root;
    private readonly string _database;
    private readonly string _logFile;
    private readonly FileSystemWatcher _watcher;
    private readonly object _sync = new();
    private Dictionary<string, string> _baseline = new(StringComparer.OrdinalIgnoreCase);

    public IntegrityMonitor(string root)
    {
        _root = Path.GetFullPath(root);

        if (!Directory.Exists(_root))
            throw new DirectoryNotFoundException($"Pasta inexistente: {_root}");

        string stateDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "MegaBrainSentinel");

        Directory.CreateDirectory(stateDirectory);

        string id = Convert.ToHexString(
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(_root)))[..16];

        _database = Path.Combine(stateDirectory, $"{id}.json");
        _logFile = Path.Combine(stateDirectory, $"{id}.log");

        _watcher = new FileSystemWatcher(_root)
        {
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.FileName
                         | NotifyFilters.DirectoryName
                         | NotifyFilters.LastWrite
                         | NotifyFilters.Size,
            InternalBufferSize = 16384,
            EnableRaisingEvents = false
        };

        _watcher.Created += (_, e) => ProcessPath(e.FullPath, "CRIADO");
        _watcher.Changed += (_, e) => ProcessPath(e.FullPath, "ALTERADO");
        _watcher.Deleted += (_, e) => ProcessPath(e.FullPath, "REMOVIDO");
        _watcher.Renamed += (_, e) =>
        {
            Log("RENOMEADO", e.OldFullPath, $"Novo caminho: {e.FullPath}");
            RefreshBaseline();
        };

        _watcher.Error += (_, e) =>
        {
            Log("ERRO", _root, e.GetException().Message);
            RefreshBaseline();
        };
    }

    private string ComputeHash(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);

        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private Dictionary<string, string> Scan()
    {
        var result = new Dictionary<string, string>(
            StringComparer.OrdinalIgnoreCase);

        foreach (string file in Directory.EnumerateFiles(
            _root, "*", SearchOption.AllDirectories))
        {
            try
            {
                result[file] = ComputeHash(file);
            }
            catch (IOException)
            {
                Log("AVISO", file, "Arquivo indisponível durante a leitura.");
            }
            catch (UnauthorizedAccessException)
            {
                Log("AVISO", file, "Acesso negado.");
            }
        }

        return result;
    }

    private void SaveBaseline()
    {
        string temporary = _database + ".tmp";
        string json = JsonSerializer.Serialize(
            _baseline,
            new JsonSerializerOptions { WriteIndented = true });

        File.WriteAllText(temporary, json);
        File.Move(temporary, _database, true);
    }

    private void Log(string action, string path, string details)
    {
        string entry = $"{DateTimeOffset.Now:O} | {action} | {path} | {details}";

        lock (_sync)
        {
            File.AppendAllText(_logFile, entry + Environment.NewLine);
        }

        Console.WriteLine(entry);
    }

    private void ProcessPath(string path, string action)
    {
        if (Directory.Exists(path))
            return;

        lock (_sync)
        {
            try
            {
                if (File.Exists(path))
                {
                    string hash = ComputeHash(path);

                    if (_baseline.TryGetValue(path, out string? oldHash))
                    {
                        if (oldHash != hash)
                        {
                            Log(action, path, $"SHA-256 anterior: {oldHash}; atual: {hash}");
                            _baseline[path] = hash;
                            SaveBaseline();
                        }
                    }
                    else
                    {
                        Log("NOVO ARQUIVO", path, $"SHA-256: {hash}");
                        _baseline[path] = hash;
                        SaveBaseline();
                    }
                }
                else if (_baseline.Remove(path))
                {
                    Log("REMOVIDO", path, "Arquivo não encontrado.");
                    SaveBaseline();
                }
            }
            catch (IOException ex)
            {
                Log("AVISO", path, ex.Message);
            }
            catch (UnauthorizedAccessException ex)
            {
                Log("AVISO", path, ex.Message);
            }
        }
    }

    private void RefreshBaseline()
    {
        lock (_sync)
        {
            _baseline = Scan();
            SaveBaseline();
        }
    }

    public void Initialize()
    {
        if (File.Exists(_database))
        {
            try
            {
                _baseline = JsonSerializer.Deserialize<Dictionary<string, string>>(
                    File.ReadAllText(_database))
                    ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }
            catch (JsonException)
            {
                Log("AVISO", _database, "Banco de integridade inválido.");
                _baseline = Scan();
                SaveBaseline();
            }
        }
        else
        {
            _baseline = Scan();
            SaveBaseline();
        }

        Console.WriteLine($"Monitorando: {_root}");
        Console.WriteLine($"Arquivos registrados: {_baseline.Count}");
        Console.WriteLine($"Log: {_logFile}");

        _watcher.EnableRaisingEvents = true;
        Log("INICIADO", _root, "Monitor de integridade ativado.");
    }

    public void Dispose()
    {
        _watcher.EnableRaisingEvents = false;
        _watcher.Dispose();
    }
}

public static class Program
{
    public static void Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("Uso: dotnet run -- <pasta>");
            return;
        }

        try
        {
            using var monitor = new IntegrityMonitor(args[0]);
            monitor.Initialize();

            Console.WriteLine("Pressione Enter para encerrar.");
            Console.ReadLine();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Erro: {ex.Message}");
            Environment.ExitCode = 1;
        }
    }
}