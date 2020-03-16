# Clam Clam Clam 
## Misc, 70 pts.

#### Description
clam clam clam clam clam clam clam clam clam `nc misc.2020.chall.actf.co` 20204 clam clam clam clam clam clam

Author: aplet123

#### Hint
U+000D

### Writeup
When we run the netcat, our terminal gets spammed with this:
```
clam{clam_clam_clam_clam_clam}
malc{malc_malc_malc_malc_malc}
clam{clam_clam_clam_clam_clam}
malc{malc_malc_malc_malc_malc}
clam{clam_clam_clam_clam_clam}
malc{malc_malc_malc_malc_malc}
clam{clam_clam_clam_clam_clam}
malc{malc_malc_malc_malc_malc}
clam{clam_clam_clam_clam_clam}
```

We get so many of these that our terminal starts slowing down. Making it run till the end seemed to be useless, it simply kept spamming and nothing changed.<br>
So I got the idea. It's spamming so many lines that I probably don't even see a lot of them, so I will take all of the output and analyze it.<br>
```
nc misc.2020.chall.actf.co > output
less output
```
After scrolling down a bit, I noticed this:
```
clam{clam_clam_clam_clam_clam}
malc{malc_malc_malc_malc_malc}
clam{clam_clam_clam_clam_clam}
type "clamclam" for salvation^Mmalc{malc_malc_malc_malc_malc}
clam{clam_clam_clam_clam_clam}
malc{malc_malc_malc_malc_malc}
clam{clam_clam_clam_clam_clam}
```

So, let's do as it says. After running `nc misc.2020.chall.actf.co` again, let's type "clamclam" and press enter.<br>

### Flag
`actf{cl4m_is_my_f4v0rite_ctfer_in_th3_w0rld}`
