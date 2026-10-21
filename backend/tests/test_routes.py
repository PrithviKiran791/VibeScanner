from tests.conftest import make_sf
from vibeguard.engine.syntax.routes import extract_units, select_for_llm

ROUTE = """import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const user = await prisma.user.findUnique({ where: { id: params.id } });
  return NextResponse.json(user);
}

export const DELETE = async () => NextResponse.json({});

function helper() {}
"""


def test_app_router_exports_http_methods_only():
    units = extract_units(make_sf("app/api/user/[id]/route.ts", ROUTE))
    assert [(u.name, u.http_method, u.line_start, u.line_end) for u in units] == [
        ("GET", "GET", 4, 7),
        ("DELETE", "DELETE", 9, 9),
    ]
    get = units[0]
    assert get.touches_db and get.reads_input and not get.has_auth_signal
    assert get.imports[1] == 'import { prisma } from "@/lib/db";'


def test_use_server_file_exports_are_actions():
    code = '"use server";\nexport async function deleteProject(id: string) {\n  await prisma.project.delete({ where: { id } });\n}\n'
    [u] = extract_units(make_sf("app/actions.ts", code))
    assert (u.kind, u.name, u.is_mutation) == ("server_action", "deleteProject", True)


def test_inline_server_action():
    code = 'export default function Page() {\n  async function save(fd: FormData) {\n    "use server";\n    await db.post.create({ data: {} });\n  }\n  return null;\n}\n'
    [u] = extract_units(make_sf("app/page.tsx", code))
    assert (u.kind, u.name, u.line_start) == ("server_action", "save", 2)


def test_express_routes_and_middleware():
    code = 'app.post("/api/users/:id", async (req, res) => { await User.findById(req.params.id); });\nre.get(x);\n'
    [u] = extract_units(make_sf("server.js", code))
    assert (u.kind, u.name, u.http_method) == ("express_route", "POST /api/users/:id", "POST")

    mw = 'export function middleware(req) { return NextResponse.next(); }\nexport const config = { matcher: ["/dashboard/:path*"] };\n'
    assert [u.kind for u in extract_units(make_sf("middleware.ts", mw))] == ["middleware"]


def test_pages_api_default_export():
    code = "export default async function handler(req, res) { res.json(await db.query('x')) }\n"
    [u] = extract_units(make_sf("pages/api/items.js", code))
    assert (u.kind, u.name) == ("api_route", "default")


def test_select_for_llm_prunes_and_prioritizes():
    units = extract_units(make_sf("app/api/user/[id]/route.ts", ROUTE))
    units += extract_units(
        make_sf(
            "app/api/health/route.ts",
            "export function GET() { return Response.json({ok: true}) }\n",
        )
    )
    picked = select_for_llm(units, max_units=10)
    assert [u.name for u in picked] == ["GET", "DELETE"]  # health check pruned
    assert len(select_for_llm(units, max_units=1)) == 1
