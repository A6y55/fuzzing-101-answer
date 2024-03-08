use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{ForkserverExecutor, TimeoutForkserverExecutor},
    feedback_and_fast, feedback_or,
    feedbacks::{MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasCorpus, StdState},
    Error, Fuzzer, StdFuzzer,
};
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
    AsMutSlice,
};

use std::{path::PathBuf, time::Duration};
const MAP_SIZE: usize = 65536;
fn main() -> Result<(), Error> {
    //corpus+input
    let corpus_dir = vec![PathBuf::from("./corpus")];
    let input_corpus = InMemoryCorpus::<BytesInput>::new();
    let timeouts_copus =
        OnDiskCorpus::new(PathBuf::from("./timeouts"))?;
    //observer
    let time_observer = TimeObserver::new("time");
    let mut shmem_provider = StdShMemProvider::new()?;
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE)?;

    shmem.write_to_env("__AFL_SHM_ID")?;
    let shmem_buf = shmem.as_mut_slice();
    let edges_observer =
        unsafe { HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)) };

    //feedback
    let mut feedback = feedback_or!(
        MaxMapFeedback::tracking(&edges_observer, true, false),
        TimeFeedback::with_observer(&time_observer)
    );
    let mut objective =
        feedback_and_fast!(TimeoutFeedback::new(), MaxMapFeedback::new(&edges_observer));

    

    //monitor
    let monitor = SimpleMonitor::new(|s| print!("{s}"));

    //event manager
    let mut mgr = SimpleEventManager::new(monitor);

    //states
    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        input_corpus,
        timeouts_copus,
        &mut feedback,
        &mut objective,
    )?;

    //scheduler
    let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

    //fuzzer
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    //executor
    let fork_server = ForkserverExecutor::builder()
        .program("./xpdf/install/bin/pdftotext")
        .parse_afl_cmdline(["@@"])
        .coverage_map_size(MAP_SIZE)
        .build(tuple_list!(time_observer, edges_observer))?;

    let timeout = Duration::from_secs(5);

    let mut executor = TimeoutForkserverExecutor::new(fork_server, timeout)?;

    // In case the corpus is empty (i.e. on first run), load existing test cases from on-disk
    // corpus
    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dir)
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to load initial corpus at {:?}: {:?}",
                    &corpus_dir, err
                )
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    //mutator + stage
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr);
    // .expect("Error in the fuzzing loop");

    Ok(())
}
