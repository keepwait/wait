#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

// 定义常量
#define SM3_BLOCK_SIZE 64
#define SM3_DIGEST_SIZE 32
#define MAX_TEST_PAIRS 10000      // 减少测试对数，加快测试速度
#define AVALANCHE_TEST_SIZE 1000  // 雪崩效应测试次数
#define BIT_FLIP_PROBABILITY 0.01 // 每个位翻转的概率

// 循环左移函数
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// 压缩函数中的常量
static const uint32_t T[64] = {
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

// 布尔函数
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | (x) & (z) | (y) & (z))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | (~(x) & (z)))

// 置换函数
#define P0(x) ((x) ^ ROTL(x, 9) ^ ROTL(x, 17))
#define P1(x) ((x) ^ ROTL(x, 15) ^ ROTL(x, 23))

// SM3上下文结构
typedef struct {
    uint32_t state[8];             // 压缩函数中间状态
    uint8_t buffer[SM3_BLOCK_SIZE]; // 消息缓冲区
    uint64_t length;               // 消息总长度(bit)
    size_t used;                   // 缓冲区已使用字节数
} sm3_context;

// 初始化上下文
void sm3_init(sm3_context *ctx) {
    memset(ctx, 0, sizeof(sm3_context));
    // 初始向量
    ctx->state[0] = 0x7380166f;
    ctx->state[1] = 0x4914b2b9;
    ctx->state[2] = 0x172442d7;
    ctx->state[3] = 0xda8a0600;
    ctx->state[4] = 0xa96f30bc;
    ctx->state[5] = 0x163138aa;
    ctx->state[6] = 0xe38dee4d;
    ctx->state[7] = 0xb0fb0e4e;
}

// 压缩函数
static void sm3_compress(sm3_context *ctx, const uint8_t block[SM3_BLOCK_SIZE]) {
    uint32_t W[68], W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    int i;

    // 消息扩展
    for (i = 0; i < 16; i++) {
        W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
               (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }

    for (i = 16; i < 68; i++) {
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15)) ^
               ROTL(W[i - 13], 7) ^ W[i - 6];
    }

    for (i = 0; i < 64; i++) {
        W1[i] = W[i] ^ W[i + 4];
    }

    // 初始化工作变量
    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    // 64轮迭代
    for (i = 0; i < 64; i++) {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[i], i)), 7);
        SS2 = SS1 ^ ROTL(A, 12);

        if (i < 16) {
            TT1 = FF0(A, B, C) + D + SS2 + W1[i];
            TT2 = GG0(E, F, G) + H + SS1 + W[i];
        } else {
            TT1 = FF1(A, B, C) + D + SS2 + W1[i];
            TT2 = GG1(E, F, G) + H + SS1 + W[i];
        }

        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    // 更新状态
    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
}

// 更新消息
void sm3_update(sm3_context *ctx, const uint8_t *data, size_t len) {
    size_t fill;

    if (len == 0)
        return;

    // 更新消息总长度
    ctx->length += (uint64_t)len * 8;

    // 如果缓冲区有数据，先填充
    if (ctx->used > 0) {
        fill = SM3_BLOCK_SIZE - ctx->used;
        if (len < fill) {
            memcpy(ctx->buffer + ctx->used, data, len);
            ctx->used += len;
            return;
        }

        memcpy(ctx->buffer + ctx->used, data, fill);
        sm3_compress(ctx, ctx->buffer);
        data += fill;
        len -= fill;
        ctx->used = 0;
    }

    // 处理完整的块
    while (len >= SM3_BLOCK_SIZE) {
        sm3_compress(ctx, data);
        data += SM3_BLOCK_SIZE;
        len -= SM3_BLOCK_SIZE;
    }

    // 保存剩余数据
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->used = len;
    }
}

// 完成计算，输出摘要
void sm3_final(sm3_context *ctx, uint8_t digest[SM3_DIGEST_SIZE]) {
    size_t fill;
    int i;

    // 填充消息
    fill = SM3_BLOCK_SIZE - ctx->used;
    if (fill == 0) {
        fill = SM3_BLOCK_SIZE;
        sm3_compress(ctx, ctx->buffer);
        memset(ctx->buffer, 0, SM3_BLOCK_SIZE);
    }

    // 填充100...（第一个字节为0x80，后续为0）
    ctx->buffer[ctx->used] = 0x80;
    if (fill > 1) {
        memset(ctx->buffer + ctx->used + 1, 0, fill - 1);
    }

    // 如果剩余空间不足以存放长度，则先压缩当前块
    if (fill <= 8) {
        sm3_compress(ctx, ctx->buffer);
        memset(ctx->buffer, 0, SM3_BLOCK_SIZE);
    }

    // 存放消息总长度(bit)，小端序转大端序
    ctx->buffer[SM3_BLOCK_SIZE - 8] = (uint8_t)(ctx->length >> 56);
    ctx->buffer[SM3_BLOCK_SIZE - 7] = (uint8_t)(ctx->length >> 48);
    ctx->buffer[SM3_BLOCK_SIZE - 6] = (uint8_t)(ctx->length >> 40);
    ctx->buffer[SM3_BLOCK_SIZE - 5] = (uint8_t)(ctx->length >> 32);
    ctx->buffer[SM3_BLOCK_SIZE - 4] = (uint8_t)(ctx->length >> 24);
    ctx->buffer[SM3_BLOCK_SIZE - 3] = (uint8_t)(ctx->length >> 16);
    ctx->buffer[SM3_BLOCK_SIZE - 2] = (uint8_t)(ctx->length >> 8);
    ctx->buffer[SM3_BLOCK_SIZE - 1] = (uint8_t)(ctx->length);

    // 压缩最后一块
    sm3_compress(ctx, ctx->buffer);

    // 将结果转换为字节数组
    for (i = 0; i < 8; i++) {
        digest[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }

    // 清空上下文
    sm3_init(ctx);
}

// 便捷函数：直接计算消息的SM3哈希
void sm3_hash(const uint8_t *data, size_t len, uint8_t digest[SM3_DIGEST_SIZE]) {
    sm3_context ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, len);
    sm3_final(&ctx, digest);
}

// 打印哈希值的辅助函数
void print_hash(const char *msg, const uint8_t digest[SM3_DIGEST_SIZE]) {
    printf("%s的SM3哈希值: ", msg);
    for (int i = 0; i < SM3_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

// 计算两个哈希值的汉明距离（不同比特数）
int hamming_distance(const uint8_t *digest1, const uint8_t *digest2) {
    int distance = 0;
    for (int i = 0; i < SM3_DIGEST_SIZE; i++) {
        uint8_t diff = digest1[i] ^ digest2[i];
        while (diff) {
            distance += diff & 1;
            diff >>= 1;
        }
    }
    return distance;
}

// 抗碰撞性测试
void collision_resistance_test() {
    printf("\n===== 抗碰撞性测试 =====\n");
    printf("测试说明：生成随机消息对，计算哈希值，寻找碰撞\n");
    printf("测试次数：%d 对消息（已减少测试量）\n\n", MAX_TEST_PAIRS);

    srand((unsigned int)time(NULL));
    int collisions = 0;
    clock_t start_time = clock();

    for (int i = 0; i < MAX_TEST_PAIRS; i++) {
        // 生成随机长度（1-128字节）的随机消息
        int len1 = rand() % 128 + 1;
        int len2 = rand() % 128 + 1;

        uint8_t msg1[128], msg2[128];
        uint8_t digest1[SM3_DIGEST_SIZE], digest2[SM3_DIGEST_SIZE];

        // 生成随机消息
        for (int j = 0; j < len1; j++)
            msg1[j] = rand() % 256;
        for (int j = 0; j < len2; j++)
            msg2[j] = rand() % 256;

        // 计算哈希值
        sm3_hash(msg1, len1, digest1);
        sm3_hash(msg2, len2, digest2);

        // 检查是否碰撞
        if (memcmp(digest1, digest2, SM3_DIGEST_SIZE) == 0) {
            collisions++;
            printf("发现碰撞！消息对 %d\n", i + 1);

            // 显示碰撞信息
            printf("消息1 (长度 %d): ", len1);
            for (int j = 0; j < (len1 < 16 ? len1 : 16); j++)
                printf("%02x", msg1[j]);
            if (len1 > 16)
                printf("...");
            printf("\n");

            printf("消息2 (长度 %d): ", len2);
            for (int j = 0; j < (len2 < 16 ? len2 : 16); j++)
                printf("%02x", msg2[j]);
            if (len2 > 16)
                printf("...");
            printf("\n");

            printf("相同的哈希值: ");
            for (int j = 0; j < SM3_DIGEST_SIZE; j++)
                printf("%02x", digest1[j]);
            printf("\n\n");
        }

        // 每1000次显示进度
        if ((i + 1) % 1000 == 0) {
            printf("已测试 %d/%d 对消息...\n", i + 1, MAX_TEST_PAIRS);
        }
    }

    clock_t end_time = clock();
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    printf("\n抗碰撞性测试结果：\n");
    printf("测试消息对数：%d\n", MAX_TEST_PAIRS);
    printf("发现碰撞数：%d\n", collisions);
    printf("碰撞概率：%e\n", (double)collisions / MAX_TEST_PAIRS);
    printf("理论碰撞概率：约 2^-128 ≈ %e\n", pow(2, -128));
    printf("测试耗时：%.2f 秒\n", elapsed_time);
    printf("\n");
}

// 雪崩效应测试
void avalanche_effect_test() {
    printf("\n===== 雪崩效应测试 =====\n");
    printf("测试说明：随机修改消息的1比特，观察哈希值的变化\n");
    printf("测试次数：%d 次\n\n", AVALANCHE_TEST_SIZE);

    srand((unsigned int)time(NULL));
    int total_bits_changed = 0;
    int min_bits_changed = SM3_DIGEST_SIZE * 8;
    int max_bits_changed = 0;
    double sum_squared_diff = 0.0;

    clock_t start_time = clock();

    for (int test = 0; test < AVALANCHE_TEST_SIZE; test++) {
        // 生成随机原始消息
        int len = rand() % 100 + 10; // 10-109字节
        uint8_t original_msg[200];
        uint8_t modified_msg[200];

        for (int i = 0; i < len; i++) {
            original_msg[i] = rand() % 256;
        }

        // 复制消息并随机修改1个比特
        memcpy(modified_msg, original_msg, len);

        // 随机选择要修改的字节和比特位
        int byte_pos = rand() % len;
        int bit_pos = rand() % 8;

        // 翻转选定的比特
        modified_msg[byte_pos] ^= (1 << bit_pos);

        // 计算原始和修改后消息的哈希值
        uint8_t original_digest[SM3_DIGEST_SIZE];
        uint8_t modified_digest[SM3_DIGEST_SIZE];

        sm3_hash(original_msg, len, original_digest);
        sm3_hash(modified_msg, len, modified_digest);

        // 计算汉明距离
        int bits_changed = hamming_distance(original_digest, modified_digest);

        total_bits_changed += bits_changed;
        if (bits_changed < min_bits_changed)
            min_bits_changed = bits_changed;
        if (bits_changed > max_bits_changed)
            max_bits_changed = bits_changed;

        // 计算方差
        double deviation = bits_changed - (SM3_DIGEST_SIZE * 8 / 2.0);
        sum_squared_diff += deviation * deviation;

        // 每100次显示进度
        if ((test + 1) % 100 == 0) {
            printf("已完成 %d/%d 次测试...\n", test + 1, AVALANCHE_TEST_SIZE);
        }
    }

    clock_t end_time = clock();
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    // 计算统计结果
    double avg_bits_changed = (double)total_bits_changed / AVALANCHE_TEST_SIZE;
    double expected_bits_changed = SM3_DIGEST_SIZE * 8 / 2.0;
    double variance = sum_squared_diff / AVALANCHE_TEST_SIZE;
    double std_dev = sqrt(variance);
    double avalanche_coefficient = avg_bits_changed / (SM3_DIGEST_SIZE * 8);

    printf("\n雪崩效应测试结果：\n");
    printf("测试次数：%d\n", AVALANCHE_TEST_SIZE);
    printf("哈希值长度：%d 比特\n", SM3_DIGEST_SIZE * 8);
    printf("理论期望变化比特数：%.1f (50%%)\n", expected_bits_changed);
    printf("\n实际统计结果：\n");
    printf("平均变化比特数：%.2f\n", avg_bits_changed);
    printf("最小变化比特数：%d\n", min_bits_changed);
    printf("最大变化比特数：%d\n", max_bits_changed);
    printf("标准差：%.2f\n", std_dev);
    printf("雪崩系数：%.4f (接近0.5为理想)\n", avalanche_coefficient);
    printf("平均变化百分比：%.2f%%\n", avalanche_coefficient * 100);
    printf("测试耗时：%.2f 秒\n", elapsed_time);

    // 评估结果
    printf("\n评估：\n");
    if (avalanche_coefficient > 0.45 && avalanche_coefficient < 0.55) {
        printf("? 雪崩效应良好：输入微小变化导致输出剧烈变化\n");
    } else if (avalanche_coefficient > 0.4 && avalanche_coefficient < 0.6) {
        printf("? 雪崩效应可接受\n");
    } else {
        printf("? 雪崩效应可能不足\n");
    }
    printf("\n");
}

// 批量雪崩效应测试（测试不同修改程度）
void batch_avalanche_test() {
    printf("\n===== 批量雪崩效应测试 =====\n");
    printf("测试不同修改程度对哈希值的影响\n\n");

    srand((unsigned int)time(NULL));

    // 原始消息
    const char *original_msg = "This is a test message for avalanche effect testing.";
    int len = (int)strlen(original_msg);

    printf("原始消息：%s\n", original_msg);
    printf("消息长度：%d 字节\n\n", len);

    // 计算原始哈希值
    uint8_t original_digest[SM3_DIGEST_SIZE];
    sm3_hash((const uint8_t *)original_msg, len, original_digest);

    printf("原始哈希值：");
    for (int i = 0; i < SM3_DIGEST_SIZE; i++)
        printf("%02x", original_digest[i]);
    printf("\n\n");

    // 定义每个级别要翻转的比特数
    int bits_to_flip_per_level[5] = {
        1, // 级别1：1比特
        2, // 级别2：2比特
        4, // 级别3：4比特
        8, // 级别4：8比特
        (int)(len * 8 * BIT_FLIP_PROBABILITY) // 级别5：约1%的比特
    };

    // 确保级别5至少翻转1个比特
    if (bits_to_flip_per_level[4] < 1)
        bits_to_flip_per_level[4] = 1;

    // 测试不同修改级别
    for (int level = 0; level < 5; level++) {
        printf("修改级别 %d：\n", level + 1);

        int total_tests = 100;
        int total_bits_changed = 0;
        int bits_to_flip = bits_to_flip_per_level[level];

        for (int test = 0; test < total_tests; test++) {
            // 创建修改后的消息
            uint8_t modified_msg[200];
            memcpy(modified_msg, original_msg, len);

            // 根据 bits_to_flip 修改相应数量的比特
            for (int flip = 0; flip < bits_to_flip; flip++) {
                int byte_pos = rand() % len;
                int bit_pos = rand() % 8;
                modified_msg[byte_pos] ^= (1 << bit_pos);
            }

            // 计算修改后哈希值
            uint8_t modified_digest[SM3_DIGEST_SIZE];
            sm3_hash(modified_msg, len, modified_digest);

            // 计算变化比特数
            total_bits_changed += hamming_distance(original_digest, modified_digest);
        }

        double avg_bits_changed = (double)total_bits_changed / total_tests;
        double percentage = avg_bits_changed / (SM3_DIGEST_SIZE * 8) * 100;

        printf("  平均修改 %d 比特\n", bits_to_flip);
        printf("  哈希值平均变化：%.1f 比特 (%.1f%%)\n", avg_bits_changed, percentage);

        if (level == 0) { // 级别1
            printf("  期望：单比特修改应导致约50%%的输出比特变化\n");
        }
        printf("\n");
    }
}

// 测试预设向量（可选功能）
void test_standard_vectors() {
    printf("\n===== 标准测试向量 =====\n");

    // 测试向量1：空消息
    uint8_t digest1[SM3_DIGEST_SIZE];
    sm3_hash(NULL, 0, digest1);
    print_hash("空消息", digest1);
    printf("预计结果: 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b\n\n");

    // 测试向量2："abc"
    const char *msg2 = "abc";
    uint8_t digest2[SM3_DIGEST_SIZE];
    sm3_hash((const uint8_t *)msg2, strlen(msg2), digest2);
    print_hash("\"abc\"", digest2);
    printf("预计结果: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0\n\n");

    // 测试向量3：长字符串
    const char *msg3 = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    uint8_t digest3[SM3_DIGEST_SIZE];
    sm3_hash((const uint8_t *)msg3, strlen(msg3), digest3);
    print_hash("\"abcd(*16)\"", digest3);
    printf("预计结果: debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732\n");
}

// 主函数：支持多种测试模式
int main() {
    char input[1024];
    uint8_t digest[SM3_DIGEST_SIZE];

    printf("===== SM3哈希算法测试套件 =====\n");
    printf("使用说明：\n");
    printf("1. 输入字符串 - 计算该字符串的哈希值\n");
    printf("2. 'test' - 查看标准测试向量\n");
    printf("3. 'collision' - 执行抗碰撞性测试（已减少测试量）\n");
    printf("4. 'avalanche' - 执行雪崩效应测试\n");
    printf("5. 'batch' - 执行批量雪崩效应测试\n");
    printf("6. 'exit' - 退出程序\n");
    printf("\n");

    while (1) {
        printf("请输入命令: ");
        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }

        // 去除换行符
        size_t len = strlen(input);
        if (len > 0 && input[len - 1] == '\n') {
            input[len - 1] = '\0';
            len--;
        }

        // 退出程序
        if (strcmp(input, "exit") == 0) {
            printf("程序退出...\n");
            break;
        }

        // 显示标准测试向量
        if (strcmp(input, "test") == 0) {
            test_standard_vectors();
            continue;
        }

        // 抗碰撞性测试
        if (strcmp(input, "collision") == 0) {
            collision_resistance_test();
            continue;
        }

        // 雪崩效应测试
        if (strcmp(input, "avalanche") == 0) {
            avalanche_effect_test();
            continue;
        }

        // 批量雪崩效应测试
        if (strcmp(input, "batch") == 0) {
            batch_avalanche_test();
            continue;
        }

        // 计算并显示哈希值
        sm3_hash((const uint8_t *)input, len, digest);
        print_hash(input, digest);
        printf("\n");
    }

    return 0;
}
