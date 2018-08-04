#!/bin/bash

NQUEUE=$1
RX_USECS=$2
TX_IFACES="ens6f1"
RX_IFACES="ens6f0"

IFACE_IRQ_SUFFIX="TxRx"
IRQ_REGEX="^[[:blank:]]*([0-9]+):.*$"

setup_rx() {
  local iface=$1 nqueue=$2 rx_usecs=$3
  local i irqno irqline

  ethtool -L $iface combined $nqueue
  ethtool -C $iface rx-usecs $rx_usecs

  for i in `seq 0 $(($nqueue - 1))`; do
    irqline=`cat /proc/interrupts | grep "${iface}-${IFACE_IRQ_SUFFIX}-${i}"`
    if [[ $irqline =~ $IRQ_REGEX ]]; then
	    echo $(( 1 << $i )) > /proc/irq/${BASH_REMATCH[1]}/smp_affinity
      echo "Set interrupt affinity $i to $iface"
    else
      echo "Cannot find irq number of ${iface}-${IFACE_IRQ_SUFFIX}-${i}"
      exit
    fi
  done
}

setup_tx() {
  local iface=$1 nqueue=$2
  ethtool -L $iface combined $nqueue
}

for iface in $RX_IFACES; do
  ip link set $iface up
  ip link set $iface promisc on
  setup_rx $iface $NQUEUE $RX_USECS
done

for iface in $TX_IFACES; do
  ip link set $iface up
  setup_tx $iface $NQUEUE
  echo "$iface should use core $count"
done

echo performance > /sys/devices/system/cpu/cpufreq/policy0/scaling_governor
echo performance > /sys/devices/system/cpu/cpufreq/policy1/scaling_governor
echo performance > /sys/devices/system/cpu/cpufreq/policy2/scaling_governor
echo performance > /sys/devices/system/cpu/cpufreq/policy3/scaling_governor
echo performance > /sys/devices/system/cpu/cpufreq/policy4/scaling_governor
echo performance > /sys/devices/system/cpu/cpufreq/policy5/scaling_governor

echo 3600000 > /sys/devices/system/cpu/cpufreq/policy0/scaling_min_freq
echo 3600000 > /sys/devices/system/cpu/cpufreq/policy1/scaling_min_freq
echo 3600000 > /sys/devices/system/cpu/cpufreq/policy2/scaling_min_freq
echo 3600000 > /sys/devices/system/cpu/cpufreq/policy3/scaling_min_freq
echo 3600000 > /sys/devices/system/cpu/cpufreq/policy4/scaling_min_freq
echo 3600000 > /sys/devices/system/cpu/cpufreq/policy5/scaling_min_freq
