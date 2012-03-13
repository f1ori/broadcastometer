#!/bin/sh

mkdir html/lib
cd html/lib/
wget http://code.jquery.com/jquery-1.7.1.min.js -O jquery-1.7.1.min.js
wget https://github.com/mbostock/d3/zipball/v2.7.3 -O d3.zip
unzip d3.zip
mv mbostock-d3-b22dd72 d3
rm d3.zip
git clone https://github.com/shutterstock/rickshaw.git

cd ../..
mkdir broadcastometer/lib
cd broadcastometer/lib/
git clone git@gitorious.org:~f1ori/qpcap/f1oris-qpcap.git qpcap
