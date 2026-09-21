import os
import re

# ==========================================================================
# MySQL 连接配置
# 优先读取环境变量；未设置时使用下方默认值（换库只需改环境变量，无需动代码）
#   DB_HOST / DB_PORT / DB_NAME / DB_USER / DB_PASSWORD
# ==========================================================================
DB_HOST = os.environ.get("DB_HOST", "")
DB_PORT = int(os.environ.get("DB_PORT", "3306"))
DB_NAME = os.environ.get("DB_NAME", "")
DB_USER = os.environ.get("DB_USER", "")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")


def _get_connection():
    """延迟导入 PyMySQL 并创建连接（Vercel 冷启动友好）。

    通过 init_command 追加 ANSI_QUOTES 到 sql_mode，使调用方沿用的
    双引号标识符（如 "username"）在 MySQL 中被当作列/表名，而非字符串字面量，
    从而无需改动 views.py / script.py 里的现有 SQL 条件写法。
    内置重试，缓解瞬时网络抖动 / 冷启动连接被拒。
    """
    if not all((DB_HOST, DB_NAME, DB_USER, DB_PASSWORD)):
        raise RuntimeError("数据库环境变量未配置：需设置 DB_HOST / DB_NAME / DB_USER / DB_PASSWORD")
    import pymysql
    last_err = None
    for attempt in range(3):
        try:
            return pymysql.connect(
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
                charset="utf8mb4",
                autocommit=False,
                connect_timeout=10,
                init_command="SET SESSION sql_mode=CONCAT(@@sql_mode, ',ANSI_QUOTES')",
            )
        except Exception as err:
            last_err = err
            print(f"[sql_db] 连接尝试 {attempt + 1}/3 失败: {err}")
            import time
            time.sleep(1)
    raise last_err


# 字段名白名单校验：拦截把用户可控字段名拼接进 SQL 造成的注入
_IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')


def _check_identifiers(names) -> None:
    """校验列名/表名仅含安全字符，非法则抛 ValueError。"""
    for name in names:
        if not _IDENT_RE.match(str(name)):
            raise ValueError(f'非法字段名: {name}')


def friendly_db_error(err) -> str:
    """将底层数据库异常翻译成对用户友好的提示（避免暴露 2013 等内部码）。"""
    s = str(err)
    if "2013" in s or "Lost connection" in s:
        return "数据库连接中断，可能是服务器防火墙/限流限制，请稍后重试或联系管理员"
    if "1044" in s or "Access denied for user" in s:
        return "数据库权限不足，请联系管理员检查账号权限"
    if "1045" in s or "Access denied" in s:
        return "数据库账号或密码错误"
    if "2003" in s or "Can't connect" in s:
        return "无法连接到数据库服务器，请确认服务已启动且网络可达"
    return "数据库错误：" + s


class DatabaseManager:
    """封装数据库连接管理的类（MySQL / PyMySQL）"""

    def __init__(self):
        self.connection = None

    def __enter__(self):
        try:
            self.connection = _get_connection()
            return self
        except Exception as err:
            print(f"数据库连接失败: {err}")
            raise

    def __exit__(self, *_):
        if self.connection:
            self.connection.close()

    def _run(self, sql: str, params=None):
        """执行 SQL。SELECT 返回结果行列表；写操作提交后返回 []；出错返回 None。"""
        try:
            with self.connection.cursor() as cur:
                cur.execute(sql, params or ())
                if cur.description is not None:
                    rows = cur.fetchall()
                    return list(rows) if rows else []
                self.connection.commit()
                return []
        except Exception as err:
            print(f"SQL 执行出错: {err}")
            try:
                self.connection.rollback()
            except Exception:
                pass
            return None

    def query_all(self, table_name: str) -> list:
        """查询指定表的所有数据"""
        rows = self._run(f'SELECT * FROM "{table_name}"')
        return rows if rows is not None else []

    def query_one(self, table_name: str, condition: str, params: tuple = ()) -> list:
        """按条件查询单条记录（返回第一个匹配行）"""
        sql = f'SELECT * FROM "{table_name}" WHERE {condition} LIMIT 1'
        rows = self._run(sql, tuple(params))
        return rows[0] if rows else None

    def query_where(self, table_name: str, condition: str, params: tuple = ()) -> list:
        """按条件查询多条记录"""
        sql = f'SELECT * FROM "{table_name}" WHERE {condition}'
        rows = self._run(sql, tuple(params))
        return rows if rows is not None else []

    def insert(self, table_name: str, data: dict) -> int:
        """插入数据到指定表（参数化查询），返回受影响的行数"""
        keys = list(data.keys())
        _check_identifiers(keys)
        try:
            values = [
                str(data[k]['values']) if isinstance(data[k], dict) and 'values' in data[k] else str(data[k])
                for k in keys
            ]
            cols = ", ".join([f'"{k}"' for k in keys])
            placeholders = ", ".join(["%s"] * len(keys))
            sql = f'INSERT INTO "{table_name}" ({cols}) VALUES ({placeholders})'
            self._run(sql, tuple(values))
            return 1
        except Exception as err:
            print(f"插入数据出错: {err}")
            return 0

    def update(self, table_name: str, data: dict, condition: str, params: tuple = ()) -> int:
        """更新指定表的数据，返回受影响的行数"""
        _check_identifiers(data.keys())
        try:
            set_clause = ", ".join([f'"{k}" = %s' for k in data.keys()])
            sql = f'UPDATE "{table_name}" SET {set_clause} WHERE {condition}'
            all_params = tuple(data.values()) + tuple(params)
            self._run(sql, all_params)
            return 1
        except Exception as err:
            print(f"更新数据出错: {err}")
            return 0

    def delete(self, table_name: str, condition: str, params: tuple = ()) -> int:
        """删除指定表的数据，返回受影响的行数"""
        try:
            sql = f'DELETE FROM "{table_name}" WHERE {condition}'
            self._run(sql, tuple(params))
            return 1
        except Exception as err:
            print(f"删除数据出错: {err}")
            return 0

    def add_columns(self, table_name: str, columns: list) -> int:
        """根据列表增加字段，返回受影响的行数,如果有该字段就不再添加"""
        try:
            # 先看是否存在该表，没有就创建
            if not self.is_table_exists(table_name):
                sql = f'CREATE TABLE "{table_name}" (id INT AUTO_INCREMENT PRIMARY KEY)'
                self._run(sql)

            for column in columns:
                rows = self._run(
                    'SELECT COUNT(*) FROM information_schema.columns '
                    'WHERE table_schema = DATABASE() AND table_name = %s AND column_name = %s',
                    (table_name, column),
                )
                if rows and rows[0][0] == 0:
                    sql = f'ALTER TABLE "{table_name}" ADD COLUMN "{column}" TEXT'
                    self._run(sql)

            return 1
        except Exception as err:
            print(f"添加字段出错: {err}")
            return 0

    def is_table_exists(self, table_name: str) -> bool:
        """检查表是否存在"""
        rows = self._run(
            'SELECT COUNT(*) FROM information_schema.tables '
            'WHERE table_schema = DATABASE() AND table_name = %s',
            (table_name,),
        )
        return rows is not None and len(rows) > 0 and rows[0][0] >= 1
