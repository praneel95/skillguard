# Publishing SkillGuard to GitHub

Everything is committed on branch `main`, tagged `v0.1.0`.

## Option A — you have `gh` (GitHub CLI) installed (easiest)
From the unzipped project folder:

```bash
gh repo create skillguard --public --source=. --remote=origin --push \
  --description "Static security scanner for AI agent skills & plugins"
git push origin v0.1.0        # push the release tag
```

## Option B — plain git (create the empty repo on github.com first)
1. Go to https://github.com/new, name it `skillguard`, **do not** add a README/license, click Create.
2. Then:

```bash
git remote add origin https://github.com/<your-username>/skillguard.git
git push -u origin main
git push origin v0.1.0
```

## Option C — start from the bundle (if you didn't keep the .git folder)
```bash
git clone skillguard.bundle skillguard
cd skillguard
# then follow Option A or B
```

## After publishing
- Enable the included CI: it runs on push automatically (`.github/workflows/ci.yml`).
- Optional PyPI release: `python -m build && twine upload dist/*`
