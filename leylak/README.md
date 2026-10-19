# Running a model on LEYLAK

One Slurm job generates everything for one model. It starts a vLLM server for
that model on a GPU node, waits until it answers, runs `generate.py` against it,
and stops the server when it is done, so the GPU is freed even if something fails.
Grading happens afterwards on the Windows machine, which has the Docker images.

## 1. One-time setup

```bash
cd ~
git clone https://github.com/LanayaC/cweft.git
cd ~/cweft
git checkout journal-extension

python3.12 -m venv ~/cweft/venv312
~/cweft/venv312/bin/pip install --upgrade pip
~/cweft/venv312/bin/pip install vllm openai anthropic httpx "python-dotenv>=1.0.0"
```

vLLM needs `ninja` at start-up; it comes with the vllm install and lives in
`~/cweft/venv312/bin`, which the job puts on its PATH.

Download each model's weights once, at the revision pinned in `config.py`
(`VLLM_REVISIONS`), so the job does not need internet access:

```bash
~/cweft/venv312/bin/hf download ibm-granite/granite-4.1-8b \
    --revision 1504002f650e656a0a3789d99574df12e3e94ed0
```

If you keep the Hugging Face cache somewhere other than `~/.cache/huggingface`,
set `HF_HOME` in your shell before submitting; the job inherits it.

## 2. Before every job: update the code

```bash
cd ~/cweft && git pull
```

## 3. Submit a job

Always submit from `~/cweft`. The first argument is the model key from
`VLLM_MODELS` in `config.py`. Anything after `--` goes to `generate.py`.

A full run on gpu5 (the default: partition `GPU_nvrtx6000pro`, 64k window).
Its logs go to a folder of their own, so they are easy to copy back:

```bash
sbatch leylak/run_model.sbatch granite-8b-bf16 -- --dataset all --logs-dir logs/granite-8b-bf16
```

Across both of gpu5's cards (tensor parallel), for the larger models:

```bash
CUDA_VISIBLE_DEVICES=0,1 sbatch leylak/run_model.sbatch granite-30b-bf16 --tp 2 -- --dataset all --logs-dir logs/granite-30b-bf16
```

LEYLAK has no GPU gres, so Slurm does not pick a card for you and you must not
pass `--gres`. The job uses card 0 unless you set `CUDA_VISIBLE_DEVICES` when
submitting, which the job inherits. To use gpu5's second card:

```bash
CUDA_VISIBLE_DEVICES=1 sbatch leylak/run_model.sbatch granite-8b-bf16 -- --dataset all --logs-dir logs/granite-8b-bf16
```

Check which cards are free first with `nvidia-smi` on the node (for example
`srun -p GPU_nvrtx6000pro -w gpu5 nvidia-smi`).

A small test on gpu4 (partition `GPU_nvrtx4090`, whose card fits a 16k window).
Test logs go to `logs/plumbing_test/`, never into a real run's folder:

```bash
sbatch -p GPU_nvrtx4090 -w gpu4 leylak/run_model.sbatch granite-8b-bf16 --max-model-len 16384 \
    -- --vulns VUL4J-77 CVE-2022-1992 --levels L1 --logs-dir logs/plumbing_test
```

Other options before `--`: `--port N` (default 8000; change it if another
server already uses that port on the node) and `--wait-timeout S` (default
1800 seconds for the server to come up). Add `--dry-run` after `--` to check a
plan without generating anything.

The GPU partitions cap a job at 12 hours (the script asks for 12:00:00; ask
for less with `--time` if you like, never more, or the job waits forever with
reason `PartitionTimeLimit`). A full run that needs longer is split into several
jobs: when one ends, submit the same command again. `generate.py` skips every
cell that already has a good log in the chosen folder, so each job continues
where the last one stopped. The same goes for a run that fails part-way.

## 4. Watch it

```bash
squeue -u $USER                           # is it queued or running?
tail -f ~/cweft_granite-8b-bf16_<jobid>.log
scancel <jobid>                           # stop it (the server is shut down too)
```

The job log shows the model, revision, window, GPUs and git commit, then
`generate.py`'s progress line by line. vLLM's own output is in
`~/cweft_<model>_<jobid>.vllm.log`; if the server fails to start, its last lines
are copied into the job log as well.

## 5. Copy the logs back to Windows

From PowerShell on the Windows machine (replace `user` and the host name with
yours). For a test:

```powershell
scp -r user@leylak:cweft/logs/plumbing_test C:\Users\lanay\cweft\logs\
```

For a full run, copy that model's folder the same way:

```powershell
scp -r user@leylak:cweft/logs/granite-8b-bf16 C:\Users\lanay\cweft\logs\
```

## 6. Grade

On Windows, from `C:\Users\lanay\cweft`, once for Vul4J and once for PatchEval.

A test, kept apart from the real results:

```powershell
python evaluate.py --logs-dir logs/plumbing_test --results-dir results/plumbing_test
python evaluate.py --dataset patcheval --logs-dir logs/plumbing_test --results-dir results/plumbing_test
```

A full run, into `results/results.csv` and `results/results_patcheval.csv`:

```powershell
python evaluate.py --logs-dir logs/granite-8b-bf16
python evaluate.py --dataset patcheval --logs-dir logs/granite-8b-bf16
```

Grading is resumable too: cells already in the results file are skipped.
