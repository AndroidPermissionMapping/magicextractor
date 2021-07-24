# magicextractor
The magicextractor create a corpus to fuzz content providers. It performs static analysis
on the given content providers. It outputs an input file which can be used to fuzz the provider.

## Setup
1. `git clone git@github.com:AndroidPermissionMapping/magicextractor.git --recurse-submodules`
2. `cd magicextractor`
3. `wget -O android_10_dex_files.tar.xz  https://dl.cispa.de/s/CCabD8JfL5eTS2g/download`
4. `mkdir extractor/dex`
4. `tar -vxf android_10_dex_files.tar.xz -C extractor/dex`
5. `rm android_10_dex_files.tar.xz`
3. `./gradlew run --args="-a android-platforms -d dex -o fuzzer_input.json -s sootOutput"`
