<div align="center">
  <h1 align="center">PPTool</h1>
  <p align="center">
    Python tool to find the loading addresses of Dart objects in libapp.so
through their pool pointer offset.
  </p>
</div>

### Support
ARM64, ARM libs

### Requierements
Python3

### Installation
Download the wheel here: https://github.com/Kirlif/PPTool/releases
   ```bash
pip install --user pptool-2.0-py3-none-any.whl
   ```

### Usage
#### from CLI<br>
pptool [-h] [-v] [-c] [-d] [-s] [-j] libapp offset [offset ...]

#### positional arguments<br>
<strong>libapp</strong>:
path to libapp.so<br>

<strong>offset</strong>:
pool pointer offsets to be searched<br>
        sequence of hex strings <br>

#### options<br>
<strong>-c</strong>:
use default color<br>

<strong>-d</strong>:
don't display assembly/disassembly<br>

<strong>-s:</strong>
create a simple output<br>

<strong>-j:</strong>
full output in JSON format<br>


#### from Python<br>
\>\>\> from pptool import pptool<br>
\>\>\> ppt = pptool()<br>
\>\>\> ppt.set_libapp(libapp)<br>
\>\>\> ppt.set_offsets(*ppo_seq)<br>
\>\>\> res = ppt.result(tree_color=True, hide_ass_disass=False)<br>
\>\>\> print(res)<br>
\>\>\> spl = ppt.simple()<br>
\>\>\> print(spl)<br>
\>\>\> jsn = ppt.json()<br>
...

