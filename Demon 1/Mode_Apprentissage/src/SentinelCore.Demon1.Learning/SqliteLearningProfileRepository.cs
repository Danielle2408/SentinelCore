using Microsoft.Data.Sqlite;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SentinelCore.Demon1.Learning;

/// <summary>SQLite learning database. Feature values and profiles are DPAPI-protected per row.</summary>
public sealed class SqliteLearningProfileRepository : IAtomicLearningRepository, IContextActivityRepository, IDisposable
{
    private const int LearningObservationRetentionHours = 24;
    private const int MaximumLearningObservationRows = 10_000;
    private const int MaximumContextActivityRowsPerProfile = 20_000;
    private readonly string _connectionString;
    private readonly int _contextRetentionDays;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };
    private bool _disposed;

    public SqliteLearningProfileRepository(string databasePath, int contextRetentionDays = 30)
    {
        _contextRetentionDays = Math.Clamp(contextRetentionDays, 1, 90);
        var fullPath = Path.GetFullPath(databasePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        _connectionString = new SqliteConnectionStringBuilder { DataSource = fullPath, Mode = SqliteOpenMode.ReadWriteCreate, Cache = SqliteCacheMode.Shared }.ToString();
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            PRAGMA busy_timeout=5000;
            PRAGMA secure_delete=ON;
            CREATE TABLE IF NOT EXISTS learning_profiles (
                sid_hash TEXT PRIMARY KEY NOT NULL,
                updated_utc TEXT NOT NULL,
                protected_profile BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS learning_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sid_hash TEXT NOT NULL,
                observed_utc TEXT NOT NULL,
                context_key TEXT NOT NULL,
                disposition TEXT NOT NULL,
                state TEXT NOT NULL,
                accepted_windows INTEGER NOT NULL,
                quality REAL NOT NULL,
                reason TEXT NOT NULL,
                protected_features BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_learning_observations_owner_date
                ON learning_observations(sid_hash, observed_utc DESC);
            CREATE TABLE IF NOT EXISTS context_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sid_hash TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                observed_utc TEXT NOT NULL,
                protected_observation BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_context_activity_profile_date
                ON context_activity(sid_hash, profile_id, observed_utc DESC);
            PRAGMA user_version=2;
            """;
        command.ExecuteNonQuery();
    }

    public LearningProfile? Load(string sid)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT protected_profile FROM learning_profiles WHERE sid_hash=$sid";
        command.Parameters.AddWithValue("$sid", HashSid(sid));
        var value = command.ExecuteScalar();
        if (value is not byte[] protectedBytes) return null;
        var json = CurrentUserDpapi.Unprotect(protectedBytes, sid);
        var profile = JsonSerializer.Deserialize<LearningProfile>(json, JsonOptions)
            ?? throw new InvalidDataException("Profil d’apprentissage vide ou illisible.");
        if (!StringComparer.Ordinal.Equals(profile.Sid, sid)) throw new InvalidDataException("Le SID du profil ne correspond pas au SID demandé.");
        return profile;
    }

    public void Save(string sid, LearningProfile profile)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!StringComparer.Ordinal.Equals(sid, profile.Sid)) throw new ArgumentException("Le SID du profil est incohérent.", nameof(profile));
        var payload = CurrentUserDpapi.Protect(JsonSerializer.SerializeToUtf8Bytes(profile, JsonOptions), sid);
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO learning_profiles(sid_hash,updated_utc,protected_profile) VALUES($sid,$updated,$payload)
            ON CONFLICT(sid_hash) DO UPDATE SET updated_utc=excluded.updated_utc, protected_profile=excluded.protected_profile;
            """;
        command.Parameters.AddWithValue("$sid", HashSid(sid));
        command.Parameters.AddWithValue("$updated", profile.UpdatedAtUtc.ToString("O"));
        command.Parameters.Add("$payload", SqliteType.Blob).Value = payload;
        command.ExecuteNonQuery();
    }

    public void Append(LearningWindow window, LearningResult result)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var protectedFeatures = CurrentUserDpapi.Protect(JsonSerializer.SerializeToUtf8Bytes(window.Features, JsonOptions), window.Sid);
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO learning_observations(sid_hash,observed_utc,context_key,disposition,state,accepted_windows,quality,reason,protected_features)
            VALUES($sid,$at,$context,$disposition,$state,$count,$quality,$reason,$features);
            """;
        command.Parameters.AddWithValue("$sid", HashSid(window.Sid));
        command.Parameters.AddWithValue("$at", window.ObservedAtUtc.ToString("O"));
        command.Parameters.AddWithValue("$context", window.ContextKey);
        command.Parameters.AddWithValue("$disposition", result.Disposition.ToString());
        command.Parameters.AddWithValue("$state", result.Report.State.ToString());
        command.Parameters.AddWithValue("$count", result.Report.AcceptedWindows);
        command.Parameters.AddWithValue("$quality", window.Quality);
        command.Parameters.AddWithValue("$reason", result.Reason);
        command.Parameters.Add("$features", SqliteType.Blob).Value = protectedFeatures;
        command.ExecuteNonQuery();
        PruneLearningHistory(connection, transaction, HashSid(window.Sid), DateTimeOffset.UtcNow);
        transaction.Commit();
    }

    public void Record(LearningWindow window, LearningResult result, LearningProfile? updatedProfile)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        var sidHash = HashSid(window.Sid);
        if (updatedProfile is not null)
        {
            var protectedProfile = CurrentUserDpapi.Protect(JsonSerializer.SerializeToUtf8Bytes(updatedProfile, JsonOptions), window.Sid);
            using var profileCommand = connection.CreateCommand();
            profileCommand.Transaction = transaction;
            profileCommand.CommandText = """
                INSERT INTO learning_profiles(sid_hash,updated_utc,protected_profile) VALUES($sid,$updated,$payload)
                ON CONFLICT(sid_hash) DO UPDATE SET updated_utc=excluded.updated_utc, protected_profile=excluded.protected_profile;
                """;
            profileCommand.Parameters.AddWithValue("$sid", sidHash);
            profileCommand.Parameters.AddWithValue("$updated", updatedProfile.UpdatedAtUtc.ToString("O"));
            profileCommand.Parameters.Add("$payload", SqliteType.Blob).Value = protectedProfile;
            profileCommand.ExecuteNonQuery();
        }

        var protectedFeatures = CurrentUserDpapi.Protect(JsonSerializer.SerializeToUtf8Bytes(window.Features, JsonOptions), window.Sid);
        using var observationCommand = connection.CreateCommand();
        observationCommand.Transaction = transaction;
        observationCommand.CommandText = """
            INSERT INTO learning_observations(sid_hash,observed_utc,context_key,disposition,state,accepted_windows,quality,reason,protected_features)
            VALUES($sid,$at,$context,$disposition,$state,$count,$quality,$reason,$features);
            """;
        observationCommand.Parameters.AddWithValue("$sid", sidHash);
        observationCommand.Parameters.AddWithValue("$at", window.ObservedAtUtc.ToString("O"));
        observationCommand.Parameters.AddWithValue("$context", window.ContextKey);
        observationCommand.Parameters.AddWithValue("$disposition", result.Disposition.ToString());
        observationCommand.Parameters.AddWithValue("$state", result.Report.State.ToString());
        observationCommand.Parameters.AddWithValue("$count", result.Report.AcceptedWindows);
        observationCommand.Parameters.AddWithValue("$quality", window.Quality);
        observationCommand.Parameters.AddWithValue("$reason", result.Reason);
        observationCommand.Parameters.Add("$features", SqliteType.Blob).Value = protectedFeatures;
        observationCommand.ExecuteNonQuery();
        PruneLearningHistory(connection, transaction, sidHash, DateTimeOffset.UtcNow);
        transaction.Commit();
    }

    public IReadOnlyList<LearningHistoryEntry> ReadRecent(string sid, int take = 100)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        take = Math.Clamp(take, 1, 1000);
        using var connection = Open();
        PruneLearningHistory(connection, null, HashSid(sid), DateTimeOffset.UtcNow);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id,observed_utc,context_key,disposition,reason,state,accepted_windows,quality,protected_features
            FROM learning_observations WHERE sid_hash=$sid ORDER BY id DESC LIMIT $take;
            """;
        command.Parameters.AddWithValue("$sid", HashSid(sid));
        command.Parameters.AddWithValue("$take", take);
        using var reader = command.ExecuteReader();
        var rows = new List<LearningHistoryEntry>();
        while (reader.Read())
        {
            var protectedFeatures = (byte[])reader[8];
            var json = CurrentUserDpapi.Unprotect(protectedFeatures, sid);
            var features = JsonSerializer.Deserialize<Dictionary<string, double>>(json, JsonOptions) ?? new(StringComparer.Ordinal);
            rows.Add(new(reader.GetInt64(0), DateTimeOffset.Parse(reader.GetString(1)), reader.GetString(2),
                Enum.Parse<SampleDisposition>(reader.GetString(3)), reader.GetString(4), Enum.Parse<LearningState>(reader.GetString(5)),
                reader.GetInt32(6), reader.GetDouble(7), features));
        }
        return rows;
    }

    public long CountObservations(string sid)
    {
        using var connection = Open();
        PruneLearningHistory(connection, null, HashSid(sid), DateTimeOffset.UtcNow);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM learning_observations WHERE sid_hash=$sid";
        command.Parameters.AddWithValue("$sid", HashSid(sid));
        return (long)(command.ExecuteScalar() ?? 0L);
    }

    /// <summary>Applies configured retention to all D1 history for this Windows user.</summary>
    public void PruneExpiredHistory(string sid)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        var sidHash = HashSid(sid);
        PruneLearningHistory(connection, transaction, sidHash, DateTimeOffset.UtcNow);
        using var profilesCommand = connection.CreateCommand();
        profilesCommand.Transaction = transaction;
        profilesCommand.CommandText = "SELECT DISTINCT profile_id FROM context_activity WHERE sid_hash=$sid";
        profilesCommand.Parameters.AddWithValue("$sid", sidHash);
        using var reader = profilesCommand.ExecuteReader();
        var profileIds = new List<string>();
        while (reader.Read()) profileIds.Add(reader.GetString(0));
        reader.Close();
        foreach (var profileId in profileIds)
        {
            ValidateProfileId(profileId);
            PruneContextActivity(connection, transaction, sidHash, profileId, DateTimeOffset.UtcNow);
        }
        transaction.Commit();
    }

    public void AppendContextActivity(string sid, ContextActivityObservation observation)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ValidateProfileId(observation.ProfileId);
        if (observation.ApplicationName.Length > 96) throw new ArgumentException("Nom d’application trop long.", nameof(observation));
        var protectedObservation = CurrentUserDpapi.Protect(JsonSerializer.SerializeToUtf8Bytes(observation, JsonOptions), sid);
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO context_activity(sid_hash,profile_id,observed_utc,protected_observation) VALUES($sid,$profile,$at,$payload)";
        command.Parameters.AddWithValue("$sid", HashSid(sid));
        command.Parameters.AddWithValue("$profile", observation.ProfileId);
        command.Parameters.AddWithValue("$at", observation.ObservedAtUtc.ToString("O"));
        command.Parameters.Add("$payload", SqliteType.Blob).Value = protectedObservation;
        command.ExecuteNonQuery();
        PruneContextActivity(connection, transaction, HashSid(sid), observation.ProfileId, DateTimeOffset.UtcNow);
        transaction.Commit();
    }

    public IReadOnlyList<ContextActivityObservation> ReadRecentContextActivity(string sid, string profileId, int take = 5000)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ValidateProfileId(profileId);
        take = Math.Clamp(take, 1, 20000);
        using var connection = Open();
        PruneContextActivity(connection, null, HashSid(sid), profileId, DateTimeOffset.UtcNow);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT protected_observation FROM context_activity WHERE sid_hash=$sid AND profile_id=$profile ORDER BY id DESC LIMIT $take";
        command.Parameters.AddWithValue("$sid", HashSid(sid));
        command.Parameters.AddWithValue("$profile", profileId);
        command.Parameters.AddWithValue("$take", take);
        using var reader = command.ExecuteReader();
        var rows = new List<ContextActivityObservation>();
        while (reader.Read())
        {
            var bytes = CurrentUserDpapi.Unprotect((byte[])reader[0], sid);
            var observation = JsonSerializer.Deserialize<ContextActivityObservation>(bytes, JsonOptions);
            if (observation is not null) rows.Add(observation);
        }
        return rows;
    }

    private void PruneLearningHistory(SqliteConnection connection, SqliteTransaction? transaction, string sidHash, DateTimeOffset nowUtc)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            DELETE FROM learning_observations
            WHERE sid_hash=$sid AND observed_utc < $cutoff;
            DELETE FROM learning_observations
            WHERE sid_hash=$sid AND id NOT IN (
                SELECT id FROM learning_observations WHERE sid_hash=$sid ORDER BY id DESC LIMIT $maximumRows);
            """;
        command.Parameters.AddWithValue("$sid", sidHash);
        command.Parameters.AddWithValue("$cutoff", nowUtc.AddHours(-LearningObservationRetentionHours).ToString("O"));
        command.Parameters.AddWithValue("$maximumRows", MaximumLearningObservationRows);
        command.ExecuteNonQuery();
    }

    private void PruneContextActivity(SqliteConnection connection, SqliteTransaction? transaction, string sidHash,
        string profileId, DateTimeOffset nowUtc)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            DELETE FROM context_activity
            WHERE sid_hash=$sid AND profile_id=$profile AND observed_utc < $cutoff;
            DELETE FROM context_activity
            WHERE sid_hash=$sid AND profile_id=$profile AND id NOT IN (
                SELECT id FROM context_activity WHERE sid_hash=$sid AND profile_id=$profile
                ORDER BY id DESC LIMIT $maximumRows);
            """;
        command.Parameters.AddWithValue("$sid", sidHash);
        command.Parameters.AddWithValue("$profile", profileId);
        command.Parameters.AddWithValue("$cutoff", nowUtc.AddDays(-_contextRetentionDays).ToString("O"));
        command.Parameters.AddWithValue("$maximumRows", MaximumContextActivityRowsPerProfile);
        command.ExecuteNonQuery();
    }

    private static void ValidateProfileId(string profileId)
    {
        if (profileId.Length is < 8 or > 16 || !profileId.StartsWith("PROFIL_", StringComparison.Ordinal)
            || !int.TryParse(profileId.AsSpan(7), out var number) || number is < 1 or > 8)
            throw new ArgumentException("Identifiant de profil invalide.", nameof(profileId));
    }

    private SqliteConnection Open()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON;";
        command.ExecuteNonQuery();
        return connection;
    }

    private static string HashSid(string sid) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sid)));
    public void Dispose() => _disposed = true;
}
