Binary aestool was not built locally on this system because the build was performed on native Windows (Windows-11-10.0.26200-SP0).

To build aestool on its native platform:
1. Clone the repository
2. mkdir build && cd build
3. cmake .. -DCMAKE_BUILD_TYPE=Release
4. cmake --build . --config Release
5. python ../scripts/package_dist.py

Alternatively, check GitHub Actions CI artifacts for automated cross-platform releases.
