// Run 219 exhaustive adjoint-code engine.
// Reads 24 x 4 uint16 row-generators followed by 4 x 16 nibble-action
// lookup values from stdin.  Exhausts all 2^24-1 nonzero adjoint words and
// all GF(16)-projective lines in the transported six-coordinate module.
#include <array>
#include <cstdint>
#include <iostream>
#include <map>
#include <utility>
#include <vector>
using namespace std;

static int rank_rows(vector<uint16_t> a) {
    int r = 0;
    for (int bit = 15; bit >= 0; --bit) {
        int p = -1;
        for (int i = r; i < (int)a.size(); ++i) {
            if ((a[i] >> bit) & 1U) { p = i; break; }
        }
        if (p < 0) continue;
        swap(a[r], a[p]);
        for (int i = 0; i < (int)a.size(); ++i) {
            if (i != r && ((a[i] >> bit) & 1U)) a[i] ^= a[r];
        }
        ++r;
        if (r == (int)a.size()) break;
    }
    return r;
}

static int rank4(array<uint16_t,4> a) {
    vector<uint16_t> v(a.begin(), a.end());
    return rank_rows(v);
}

static array<uint16_t,4> rows_for(
    uint32_t y,
    const array<array<uint16_t,4>,24>& B
) {
    array<uint16_t,4> r{0,0,0,0};
    while (y) {
        int i = __builtin_ctz(y);
        y &= y - 1;
        for (int j = 0; j < 4; ++j) r[j] ^= B[i][j];
    }
    return r;
}

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    array<array<uint16_t,4>,24> B{};
    for (int i = 0; i < 24; ++i)
        for (int j = 0; j < 4; ++j)
            cin >> B[i][j];

    // Four F2-basis scalars 1,2,4,8, each as a 16-entry action table on one
    // transported GF(16) coordinate nibble.
    int L[4][16]{};
    for (int a = 0; a < 4; ++a)
        for (int x = 0; x < 16; ++x)
            cin >> L[a][x];

    array<uint64_t,5> rank_hist{0,0,0,0,0};
    array<uint16_t,4> cur{0,0,0,0};
    uint32_t prev = 0;

    for (uint32_t k = 1; k < (1u << 24); ++k) {
        uint32_t g = k ^ (k >> 1);
        uint32_t diff = g ^ prev;
        int idx = __builtin_ctz(diff);
        for (int j = 0; j < 4; ++j) cur[j] ^= B[idx][j];
        prev = g;
        ++rank_hist[rank4(cur)];
    }

    // One representative per transported GF(16)-projective line:
    // the first nonzero 4-bit coordinate is normalized to raw coordinate 1.
    map<pair<int,int>, uint64_t> line_hist;
    uint64_t projective_total = 0;
    for (int pos = 0; pos < 6; ++pos) {
        uint32_t prefix = 1u << (4 * pos);
        uint64_t tails = 1ull << (4 * (5 - pos));
        for (uint64_t z = 0; z < tails; ++z) {
            uint32_t y = prefix | ((uint32_t)z << (4 * (pos + 1)));
            auto rr = rows_for(y, B);
            int representative_rank = rank4(rr);

            vector<uint16_t> all_rows;
            all_rows.reserve(16);
            for (int a = 0; a < 4; ++a) {
                uint32_t yy = 0;
                for (int block = 0; block < 6; ++block) {
                    int x = (y >> (4 * block)) & 15;
                    yy |= (uint32_t)L[a][x] << (4 * block);
                }
                auto rs = rows_for(yy, B);
                for (auto row : rs) all_rows.push_back(row);
            }
            int line_support = rank_rows(all_rows);
            ++line_hist[{representative_rank, line_support}];
            ++projective_total;
        }
    }

    cout << "{\n";
    cout << "  \"rank_histogram\": {";
    for (int r = 0; r <= 4; ++r) {
        if (r) cout << ", ";
        cout << "\"" << r << "\": " << rank_hist[r];
    }
    cout << "},\n";
    cout << "  \"projective_line_total\": " << projective_total << ",\n";
    cout << "  \"field_line_histogram\": [\n";
    bool first = true;
    for (const auto& kv : line_hist) {
        if (!first) cout << ",\n";
        first = false;
        cout << "    {\"representative_rank\": " << kv.first.first
             << ", \"row_support\": " << kv.first.second
             << ", \"count\": " << kv.second << "}";
    }
    cout << "\n  ]\n";
    cout << "}\n";
    return 0;
}
