using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SentinelCore.Demon1.Core;

public enum ProfileState { NO_PROFILE, CALIBRATING, INSUFFICIENT_DATA, LOW_MATURITY, MATURE, DEGRADED, CONFLICT, FROZEN }
public enum AdmissionStatus { Admitted, Quarantined, Rejected }
public sealed record FeatureResult(string Name, double? Observed, double? Median, double? Mad, double? Iqr, double? Deviation, double Quality, bool IsAnomalous, string Reason);
public sealed record BehaviorObservation(string Sid, DateTimeOffset TimestampUtc, IReadOnlyDictionary<string,double> NumericFeatures, string? AppCategory, string SessionState, string? LocalRemote, double Quality, bool ConsentEnabled, bool SensorDegraded=false, bool ConflictingSignals=false, bool SeriousThreatFromD2=false, bool GuardSuspicion=false);
public sealed record BehaviorReport(string Sid, ProfileState State, double AnomalyLevel, double Confidence, IReadOnlyList<FeatureResult> Features, string Summary, string AdmissionReason);
public sealed record ProfileSnapshot(int Version, DateTimeOffset CreatedUtc, DateTimeOffset UpdatedUtc, int AcceptedCount, int DistinctDays, Dictionary<string,List<double>> NumericSamples, Dictionary<string,int> AppCounts, Dictionary<string,int> WeeklyHourCounts, List<string> DayKeys, bool LearningFrozen, string IntegrityHash);
public sealed record LearningDecision(AdmissionStatus Status, string Reason);
public sealed record InterDaemonEnvelope(Guid MessageId,string CorrelationId,DateTimeOffset TimestampUtc,string SourceDaemon,string Destination,string MessageType,int SchemaVersion,DateTimeOffset ExpiresAtUtc,JsonElement Payload);

public interface ILearningAdmissionPolicy { LearningDecision Evaluate(BehaviorObservation observation, BehaviorReport report); }
public interface IProfileStore { ProfileSnapshot? Load(string sid); void Save(string sid, ProfileSnapshot snapshot); void RecordRejected(string sid,DateTimeOffset at,string reason,IReadOnlyCollection<string> featureNames); }
public interface IInterDaemonBus { ValueTask PublishAsync(InterDaemonEnvelope message,CancellationToken ct=default); }

public sealed class ConservativeAdmissionPolicy : ILearningAdmissionPolicy
{
    public LearningDecision Evaluate(BehaviorObservation o, BehaviorReport r)
    {
        if (!o.ConsentEnabled) return new(AdmissionStatus.Rejected,"Consentement désactivé.");
        if (!double.IsFinite(o.Quality) || o.Quality is < 0 or > 1) return new(AdmissionStatus.Quarantined,"Qualité d’observation invalide.");
        if (o.SeriousThreatFromD2) return new(AdmissionStatus.Quarantined,"Finding sérieux D2: apprentissage gelé.");
        if (o.GuardSuspicion) return new(AdmissionStatus.Quarantined,"Suspicion Guard: observation mise en quarantaine.");
        if (o.ConflictingSignals) return new(AdmissionStatus.Quarantined,"Signaux contradictoires.");
        if (o.SensorDegraded || o.Quality < 0.80) return new(AdmissionStatus.Quarantined,"Qualité/capteur insuffisant.");
        if (r.Features.Any(f=>f.IsAnomalous)) return new(AdmissionStatus.Quarantined,"Au moins une caractéristique atypique: ne pas contaminer le profil.");
        return new(AdmissionStatus.Admitted,"Observation admissible; adaptation bornée.");
    }
}

public sealed class BehaviorEngine(IProfileStore store, ILearningAdmissionPolicy admission, int minSamplesPerFeature=8, int matureSamples=60, int matureDays=7)
{
    private readonly IProfileStore _store=store; private readonly ILearningAdmissionPolicy _admission=admission;
    public BehaviorReport Process(BehaviorObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);
        var invalidReason = ValidateObservation(observation);
        if (invalidReason is not null)
            return new(observation.Sid ?? string.Empty, ProfileState.DEGRADED, 0, 0, [],
                "Observation invalide; apprentissage ignoré.", $"{AdmissionStatus.Quarantined}: {invalidReason}");

        var profile=_store.Load(observation.Sid) ?? Empty();
        var results=new List<FeatureResult>();
        foreach(var (name,value) in observation.NumericFeatures)
        {
            if (!double.IsFinite(value)) { results.Add(new(name,null,null,null,null,null,0,false,"Valeur non finie ignorée.")); continue; }
            profile.NumericSamples.TryGetValue(name,out var prior); prior ??=[];
            var med=Median(prior); var mad=prior.Count>0?Median(prior.Select(x=>Math.Abs(x-med)).ToList()):0;
            var q1=Quantile(prior,.25); var q3=Quantile(prior,.75); var iqr=q3-q1;
            var enough=prior.Count>=minSamplesPerFeature;
            var scale=Math.Max(1.4826*mad, iqr/1.349); var deviation=enough?(scale>1e-9?Math.Abs(value-med)/scale:(Math.Abs(value-med)<1e-9?0:8)):0;
            // Cap score; when baseline is constant, any difference is surfaced but confidence stays low until mature.
            var anomalous=enough && deviation>=3.5;
            results.Add(new(name,value,enough?med:null,enough?mad:null,enough?iqr:null,enough?deviation:null,observation.Quality,anomalous,enough?(anomalous?"Écart robuste supérieur au seuil 3.5.":"Dans la plage robuste observée."):"Échantillon insuffisant."));
        }
        var hourKey=$"{(int)observation.TimestampUtc.DayOfWeek}:{observation.TimestampUtc.Hour/2}";
        profile.WeeklyHourCounts.TryGetValue(hourKey,out var hourCount);
        var timeMature=profile.AcceptedCount>=minSamplesPerFeature;
        if(timeMature) results.Add(new("weekly_time_bucket",hourCount, hourCount, null,null,hourCount==0?4:0,observation.Quality,hourCount==0,"Créneau de deux heures par jour de semaine; aucune circularité linéaire."));
        var appCount=0; if(observation.AppCategory is not null) profile.AppCounts.TryGetValue(observation.AppCategory,out appCount);
        var appMature=profile.AcceptedCount>=minSamplesPerFeature;
        if(appMature && observation.AppCategory is not null) results.Add(new("application_category",appCount,appCount,null,null,appCount==0?3:0,observation.Quality,appCount==0,"Rareté de catégorie, jamais verdict isolé."));
        var flagged=results.Count(x=>x.IsAnomalous); var applicable=results.Count(x=>x.Deviation.HasValue);
        var anomaly=applicable==0?0:Math.Min(1.0,flagged/(double)Math.Max(2,applicable)+results.Where(x=>x.Deviation.HasValue).Select(x=>Math.Min(8,x.Deviation??0)).DefaultIfEmpty().Average()/20);
        var confidence=Math.Min(1,profile.AcceptedCount/(double)matureSamples)*Math.Min(1,profile.DistinctDays/(double)matureDays)*Math.Clamp(observation.Quality,0,1);
        var state=profile.LearningFrozen||observation.SeriousThreatFromD2||observation.GuardSuspicion?ProfileState.FROZEN:observation.ConflictingSignals?ProfileState.CONFLICT:observation.SensorDegraded?ProfileState.DEGRADED:profile.AcceptedCount==0?ProfileState.NO_PROFILE:profile.AcceptedCount<minSamplesPerFeature?ProfileState.CALIBRATING:profile.AcceptedCount<matureSamples||profile.DistinctDays<matureDays?ProfileState.LOW_MATURITY:ProfileState.MATURE;
        var provisional=new BehaviorReport(observation.Sid,state,anomaly,confidence,new ReadOnlyCollection<FeatureResult>(results),$"{flagged} caractéristique(s) atypique(s) sur {applicable} évaluables; écart ≠ preuve d'intrusion.","");
        var decision=profile.LearningFrozen?new LearningDecision(AdmissionStatus.Quarantined,"Apprentissage gelé; reprise authentifiée requise."):_admission.Evaluate(observation,provisional);
        if(decision.Status==AdmissionStatus.Admitted && !profile.LearningFrozen) { profile=Update(profile,observation); _store.Save(observation.Sid,profile); }
        else { _store.RecordRejected(observation.Sid,observation.TimestampUtc,decision.Reason,observation.NumericFeatures.Keys.ToArray()); if(observation.SeriousThreatFromD2||observation.GuardSuspicion) { profile=profile with{LearningFrozen=true,Version=profile.Version+1,UpdatedUtc=observation.TimestampUtc}; _store.Save(observation.Sid,profile); } }
        return provisional with { AdmissionReason=$"{decision.Status}: {decision.Reason}" };
    }

    private static string? ValidateObservation(BehaviorObservation observation)
    {
        if (string.IsNullOrWhiteSpace(observation.Sid) || observation.Sid.Length > 128
            || observation.Sid.Any(char.IsControl)) return "Identifiant de session invalide.";
        if (observation.TimestampUtc.Offset != TimeSpan.Zero) return "L’horodatage doit être en UTC.";
        if (!double.IsFinite(observation.Quality) || observation.Quality is < 0 or > 1)
            return "La qualité doit être un nombre fini compris entre 0 et 1.";
        if (observation.NumericFeatures is null || observation.NumericFeatures.Count > 64)
            return "Le nombre de caractéristiques est invalide.";
        foreach (var (name, value) in observation.NumericFeatures)
        {
            if (string.IsNullOrWhiteSpace(name) || name.Length > 64
                || name.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('_' or '-' or '.')))
                return "Nom de caractéristique invalide.";
            if (!double.IsFinite(value) || Math.Abs(value) > 1_000_000_000)
                return "Valeur de caractéristique non finie ou hors limites.";
        }
        if (observation.AppCategory is { } app
            && (app.Length > 64 || app.Any(c => char.IsControl(c)))) return "Catégorie d’application invalide.";
        if (string.IsNullOrWhiteSpace(observation.SessionState) || observation.SessionState.Length > 32
            || observation.SessionState.Any(char.IsControl)) return "État de session invalide.";
        if (observation.LocalRemote is { } locality
            && (locality.Length > 32 || locality.Any(char.IsControl))) return "État local/distant invalide.";
        return null;
    }
    public bool ResumeLearning(string sid,bool ownerVerified)
    {
        if(!ownerVerified)return false;var profile=_store.Load(sid);if(profile is null||!profile.LearningFrozen)return false;
        _store.Save(sid,profile with{LearningFrozen=false,Version=profile.Version+1,UpdatedUtc=DateTimeOffset.UtcNow});return true;
    }
    private static ProfileSnapshot Update(ProfileSnapshot p,BehaviorObservation o)
    {
        var nums=p.NumericSamples.ToDictionary(x=>x.Key,x=>new List<double>(x.Value));
        foreach(var (k,v) in o.NumericFeatures) { if(!double.IsFinite(v))continue; if(!nums.TryGetValue(k,out var list))nums[k]=list=[]; list.Add(v); if(list.Count>256)list.RemoveAt(0); }
        var apps=new Dictionary<string,int>(p.AppCounts); if(o.AppCategory is not null)apps[o.AppCategory]=apps.GetValueOrDefault(o.AppCategory)+1;
        var hours=new Dictionary<string,int>(p.WeeklyHourCounts);var hk=$"{(int)o.TimestampUtc.DayOfWeek}:{o.TimestampUtc.Hour/2}";hours[hk]=hours.GetValueOrDefault(hk)+1;
        var days=new List<string>(p.DayKeys);var day=o.TimestampUtc.UtcDateTime.ToString("yyyy-MM-dd");if(!days.Contains(day))days.Add(day);if(days.Count>365)days.RemoveAt(0);
        var version=p.Version+(o.TimestampUtc.UtcDateTime.Date>p.UpdatedUtc.UtcDateTime.Date?1:0); var updated=p with{Version=version,NumericSamples=nums,AppCounts=apps,WeeklyHourCounts=hours,DayKeys=days,AcceptedCount=p.AcceptedCount+1,DistinctDays=days.Count,UpdatedUtc=o.TimestampUtc,IntegrityHash=""};
        return updated with{IntegrityHash=ProfileHash(updated)};
    }
    private static ProfileSnapshot Empty()=>new(1,DateTimeOffset.UtcNow,DateTimeOffset.UtcNow,0,0,[],[],[],[],false,"");
    private static double Median(List<double> v){if(v.Count==0)return 0;var a=v.Order().ToArray();return a.Length%2==1?a[a.Length/2]:(a[a.Length/2-1]+a[a.Length/2])/2;}
    private static double Quantile(List<double> v,double q){if(v.Count==0)return 0;var a=v.Order().ToArray();var pos=(a.Length-1)*q;var lo=(int)Math.Floor(pos);var hi=(int)Math.Ceiling(pos);return a[lo]+(a[hi]-a[lo])*(pos-lo);}
    private static string ProfileHash(ProfileSnapshot p){var copy=p with{IntegrityHash=""};return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(copy))));}
}

public sealed class InMemoryProfileStore : IProfileStore
{
    private readonly Dictionary<string,ProfileSnapshot> _items=new(StringComparer.Ordinal);
    public ProfileSnapshot? Load(string sid)=>_items.GetValueOrDefault(sid);
    public void Save(string sid,ProfileSnapshot snapshot)=>_items[sid]=snapshot;
    public void RecordRejected(string sid,DateTimeOffset at,string reason,IReadOnlyCollection<string> featureNames){}
}

public sealed class JsonlSimulationBus(string filePath) : IInterDaemonBus
{
    private readonly string _path=filePath;
    public async ValueTask PublishAsync(InterDaemonEnvelope m,CancellationToken ct=default)
    {
        if(m.SchemaVersion!=1 || m.SourceDaemon!="HumanBehaviorMonitor" || m.Destination!="RiskResponseGuard") throw new InvalidOperationException("Envelope incompatible avec le contrat D1 v1.");
        var bytes=JsonSerializer.SerializeToUtf8Bytes(m); if(bytes.Length>64*1024)throw new InvalidOperationException("Message supérieur à la limite commune de 64 KiB.");
        await File.AppendAllTextAsync(_path,JsonSerializer.Serialize(m)+Environment.NewLine,Encoding.UTF8,ct);
    }
}

public sealed class BehaviorPublisher(IInterDaemonBus bus)
{
 public async ValueTask PublishAsync(BehaviorReport report,string correlationId,CancellationToken ct=default)
 {
  var type=report.AnomalyLevel>=0.35?"BEHAVIOR_DEVIATION":"USER_CONTEXT";
  var codes=report.Features.Where(f=>f.IsAnomalous).Select(f=>f.Name).Distinct().ToArray();
  var payload=type=="BEHAVIOR_DEVIATION"?JsonSerializer.SerializeToElement(new{deviationCodes=codes,observedWindowSeconds=60,sensorAvailability="available",baselineVersion=1,confidenceBand=report.Confidence<0.25?"low":report.Confidence<0.7?"medium":"high",profileState=report.State.ToString()}):JsonSerializer.SerializeToElement(new{sessionState="observed",interactionBand="aggregated",timeDeviationBand=codes.Contains("weekly_time_bucket")?"unusual":"typical",profileMaturity=report.State.ToString(),confidenceBand=report.Confidence<0.25?"low":report.Confidence<0.7?"medium":"high",consentState="enabled"});
  var now=DateTimeOffset.UtcNow; await bus.PublishAsync(new(Guid.NewGuid(),correlationId,now,"HumanBehaviorMonitor","RiskResponseGuard",type,1,now.AddSeconds(30),payload),ct);
 }
}
