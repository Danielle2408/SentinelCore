using SentinelCore.Demon1.Core;
using SentinelCore.Demon1.Learning;
using SentinelCore.Demon1.VisualVerification;
using System.Text.Json;
static void Check(bool ok,string m){if(!ok)throw new Exception(m);Console.WriteLine("PASS "+m);}
var store=new InMemoryProfileStore();var engine=new BehaviorEngine(store,new ConservativeAdmissionPolicy(),8,20,5);var sid="sid-test";var start=new DateTimeOffset(2026,1,1,8,0,0,TimeSpan.Zero);for(int i=0;i<12;i++)engine.Process(new(sid,start.AddDays(i),new Dictionary<string,double>{{"typing",100+(i%3)},{"mouse",10+(i%2)}},"development","active","local",1,true));Check(store.Load(sid)!.AcceptedCount==12,"baseline admission");var anomal=engine.Process(new(sid,start.AddDays(13),new Dictionary<string,double>{{"typing",300},{"mouse",11}},"development","active","local",1,true));Check(anomal.Features.Any(x=>x.Name=="typing"&&x.IsAnomalous),"robust anomaly");Check(store.Load(sid)!.AcceptedCount==12,"contamination prevention");var frozen=engine.Process(new(sid,start.AddDays(14),new Dictionary<string,double>{{"typing",101}},"development","active","local",1,true,SeriousThreatFromD2:true));Check(frozen.State==ProfileState.FROZEN&&store.Load(sid)!.AcceptedCount==12&&store.Load(sid)!.LearningFrozen,"D2 finding freezes learning");var stillFrozen=engine.Process(new(sid,start.AddDays(15),new Dictionary<string,double>{{"typing",101}},"development","active","local",1,true));Check(stillFrozen.State==ProfileState.FROZEN&&store.Load(sid)!.AcceptedCount==12,"freeze persists across later observations");Check(!engine.ResumeLearning(sid,false)&&engine.ResumeLearning(sid,true),"only verified owner resumes learning");engine.Process(new("other",start,new Dictionary<string,double>{{"typing",5}},"other","active","local",1,false));Check(store.Load("other")==null,"consent gate");
var invalidInputStore=new InMemoryProfileStore();var inputGuard=new BehaviorEngine(invalidInputStore,new ConservativeAdmissionPolicy());
var invalidQuality=inputGuard.Process(new("bad-quality",start,new Dictionary<string,double>{{"typing",100}},"development","active","local",double.NaN,true));
Check(invalidQuality.State==ProfileState.DEGRADED&&invalidQuality.Confidence==0&&invalidInputStore.Load("bad-quality") is null,"non-finite quality rejected without profile update");
var invalidFeature=inputGuard.Process(new("bad-feature",start,new Dictionary<string,double>{{"typing",double.PositiveInfinity}},"development","active","local",1,true));
Check(invalidFeature.State==ProfileState.DEGRADED&&invalidInputStore.Load("bad-feature") is null,"non-finite feature rejected without profile update");
var outOfRangeQuality=inputGuard.Process(new("out-of-range-quality",start,new Dictionary<string,double>{{"typing",100}},"development","active","local",1.01,true));
Check(outOfRangeQuality.State==ProfileState.DEGRADED&&invalidInputStore.Load("out-of-range-quality") is null,"out-of-range quality rejected without profile update");
var retentionDb=Path.Combine(Path.GetTempPath(),"D1-learning-retention-"+Guid.NewGuid()+".db");
using(var retentionRepository=new SqliteLearningProfileRepository(retentionDb,7))
{
    var retentionNow=DateTimeOffset.UtcNow;
    var retentionReport=new LearningReport(LearningState.CALIBRATING,1,1,0,1,1,new Dictionary<string,FeatureBaseline>(),"fixture");
    var retentionResult=new LearningResult(SampleDisposition.ACCEPTED,"fixture",retentionReport);
    var retentionSid="sid-retention-test";
    var retentionContext="PROFIL_1|LOCAL|DEFAULT_KB|DEFAULT_MOUSE";
    retentionRepository.Append(new(retentionSid,retentionNow.AddHours(-25),retentionContext,new Dictionary<string,double>{{"typing.rate",30}},1,OwnerVerification.OWNER_CONFIRMED,InputOrigin.PHYSICAL_DEVICE,ThreatContext.CLEAR),retentionResult);
    retentionRepository.Append(new(retentionSid,retentionNow.AddHours(-12),retentionContext,new Dictionary<string,double>{{"typing.rate",31}},1,OwnerVerification.OWNER_CONFIRMED,InputOrigin.PHYSICAL_DEVICE,ThreatContext.CLEAR),retentionResult);
    retentionRepository.PruneExpiredHistory(retentionSid);
    Check(retentionRepository.CountObservations(retentionSid)==1,"learning event history expires after 24 hours");
    retentionRepository.AppendContextActivity(retentionSid,new("PROFIL_1",retentionNow.AddDays(-8),"oldapp",8,1,15,2,100,40));
    retentionRepository.AppendContextActivity(retentionSid,new("PROFIL_1",retentionNow.AddDays(-1),"currentapp",9,2,15,3,120,45));
    retentionRepository.PruneExpiredHistory(retentionSid);
    var retainedActivity=retentionRepository.ReadRecentContextActivity(retentionSid,"PROFIL_1",100);
    Check(retainedActivity.Count==1&&retainedActivity[0].ApplicationName=="currentapp","application and resource history follows configured seven-day retention");
}
var cases=JsonSerializer.Deserialize<List<Fixture>>(File.ReadAllText(Path.Combine(AppContext.BaseDirectory,"training-cases.json")))!;Check(cases.Count==50,"50 published D1 scenarios loaded");int checkedCases=0;foreach(var f in cases){var local=new InMemoryProfileStore();var e=new BehaviorEngine(local,new ConservativeAdmissionPolicy(),8,20,5);var id=f.scenario_id;for(int i=0;i<10;i++)e.Process(new(id,start.AddDays(i),new Dictionary<string,double>{{"typing",100+(i%3)},{"mouse",10+(i%2)}},"development","active","local",1,true));var obs=new BehaviorObservation(id,start.AddDays(11),new Dictionary<string,double>{{"typing",f.label=="suspicious"?250:101},{"mouse",11}},"development","active","local",f.label=="uncertain"?.3:1,true,SensorDegraded:f.label=="uncertain");var result=e.Process(obs);if(f.label=="suspicious")Check(result.Features.Any(x=>x.IsAnomalous)&&local.Load(id)!.AcceptedCount==10,$"{id} threat excluded");else if(f.label=="uncertain")Check(result.State==ProfileState.DEGRADED&&local.Load(id)!.AcceptedCount==10,$"{id} degraded excluded");else Check(local.Load(id)!.AcceptedCount==11,$"{id} benign admitted");checkedCases++;}Check(checkedCases==50,"all training/validation cases replayed");var busPath=Path.Combine(Path.GetTempPath(),Guid.NewGuid()+".jsonl");var publisher=new BehaviorPublisher(new JsonlSimulationBus(busPath));publisher.PublishAsync(anomal,"case-test").AsTask().GetAwaiter().GetResult();var wire=File.ReadAllText(busPath);Check(wire.Contains("BEHAVIOR_DEVIATION")&&wire.Contains("RiskResponseGuard"),"published v1 Guard message");Check(!wire.Contains("300"),"raw feature values are not sent to Guard");
var directory=Path.Combine(Path.GetTempPath(),"D1-profile-test-"+Guid.NewGuid());var dpapi=new DpapiVersionedProfileStore(directory);var saved=store.Load(sid)!;dpapi.Save(sid,saved);Check(dpapi.Load(sid)?.AcceptedCount==saved.AcceptedCount,"DPAPI profile round trip");Check(dpapi.ListHistory(sid).Count>0,"version history created");Check(!dpapi.RestoreVersion(sid,1,false),"history restore requires verified owner");dpapi.Save(sid,saved with{Version=2,UpdatedUtc=DateTimeOffset.UtcNow.AddDays(1)});Check(dpapi.RestoreVersion(sid,saved.Version,true),"verified owner can restore an earlier profile version");
Check(LivenessDecisionPolicy.ClassifyAverage(.60) == LivenessResult.LIVE, "liveness accepts the configured 0.60 threshold");
Check(LivenessDecisionPolicy.ClassifyAverage(.40) == LivenessResult.SPOOF_SUSPECTED, "liveness rejects clear spoof-range scores");
Check(LivenessDecisionPolicy.ClassifyAverage(.493) == LivenessResult.INDETERMINATE, "liveness does not label an uncertain 0.493 score as spoof");
var visualFake = new FakeVisualIdentityVerifier(id => new(id, DateTimeOffset.UtcNow, VisualMatch.MATCH,
    LivenessResult.LIVE, "OWNER_1", .82, .91, 8, null, "PROFILE_MATCH_AND_LIVENESS_CONFIRMED"));
var visualHandler = new Demon1VisualRequestHandler(visualFake, () => true);
var requestNow = DateTimeOffset.UtcNow;
var invalidPurpose = visualHandler.HandleAsync(new("test-purpose", "LOGIN", requestNow, requestNow.AddSeconds(10))).GetAwaiter().GetResult();
Check(invalidPurpose.ReasonCode == "VISUAL_REQUEST_PURPOSE_NOT_ALLOWED" && visualFake.Calls == 0, "invalid D3 purpose is rejected before verifier call");
var expiredRequest = visualHandler.HandleAsync(new("test-expired", "SUSPICION", requestNow.AddSeconds(-2), requestNow.AddSeconds(-1))).GetAwaiter().GetResult();
Check(expiredRequest.ReasonCode == "VISUAL_REQUEST_EXPIRED" && visualFake.Calls == 0, "expired D3 request is rejected before verifier call");
var validRequest = visualHandler.HandleAsync(new("test-match", "ALERT", requestNow, requestNow.AddSeconds(30))).GetAwaiter().GetResult();
Check(validRequest.Status == "MATCH" && validRequest.ProfileId == "OWNER_1" && visualFake.Calls == 1, "D1 visual handler returns the correlated owner result");
var unsafeFake = new FakeVisualIdentityVerifier(id => new(id, DateTimeOffset.UtcNow, VisualMatch.MATCH,
    LivenessResult.INDETERMINATE, "OWNER_1", .82, .91, 8, null, "BAD_FIXTURE"));
var unsafeResult = new Demon1VisualRequestHandler(unsafeFake, () => true)
    .HandleAsync(new("test-unsafe-match", "SUSPICION", requestNow, requestNow.AddSeconds(30))).GetAwaiter().GetResult();
Check(unsafeResult.Status == "INDETERMINATE" && unsafeResult.ReasonCode == "VISUAL_MATCH_INVARIANT_REJECTED", "D1 blocks MATCH without confirmed liveness");
await BackgroundBrokerChecks.RunAsync(Check);
NamedPipeProtocolChecks.RunAsync().GetAwaiter().GetResult();
Console.WriteLine("All D1 checks passed.");
record Fixture(string scenario_id,string label);

sealed class FakeVisualIdentityVerifier(Func<string, VisualCheckResult> createResult) : IVisualIdentityVerifier
{
    public int Calls { get; private set; }
    public Task<VisualCheckResult> VerifyAlertAsync(string correlationId, CancellationToken cancellationToken = default)
    {
        Calls++;
        return Task.FromResult(createResult(correlationId));
    }
    public byte[]? ReadEvidence(string evidenceRef) => null;
}

