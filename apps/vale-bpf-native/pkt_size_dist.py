from vale_bpf_native import VALE_BPF_NATIVE
import time


b = VALE_BPF_NATIVE(src_file="pkt_size_dist.c")
b.attach_vale_bpf_native("vale0:", "pkt_size_dist")

pkt_cnt = b.get_table("pkt_cnt")

prev = [0] * 5
print("Printing drops per IP protocol-number, hit CTRL+C to stop")
while 1:
    try:
        for k in pkt_cnt.keys():
            val = pkt_cnt.sum(k).value
            if val:
                i = k.value
                if val:
                    delta = val - prev[i]
                    prev[i] = val

                    s = ""
                    if i == 0:
                        s = "0 - 300"
                    elif i == 1:
                        s = "301 - 600"
                    elif i == 2:
                        s = "601 - 900"
                    elif i == 3:
                        s = "901 - 1200"
                    elif i == 4:
                        s = "1201 - 1500"
                    else:
                        break

                    print("%13s: %f Mpps" % (s, float(delta) / 1000 / 1000))
        time.sleep(1)

    except KeyboardInterrupt:
        print("Removing filter from device")
        break;
