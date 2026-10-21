using System.Collections.Generic;

namespace GeregeSystems.EidMongolia.Pades.Pdf;

/// <summary>Where the stamp ended up (visible page space, h100) and why — Go core.Placement.</summary>
internal sealed record PlaceResult(long X, long Y, PlacementStatus Status);

/// <summary>
/// Stamp placement — PLACEMENT_SPEC.md §6 (Go pades/internal/core/placement.go). The requested rect (visible page space,
/// h100) is the first candidate; when it collides with the page's occupancy the stamp moves to the first free candidate.
/// </summary>
internal static class StampPlacement
{
    private const long Pad = 400; // h100: clearance kept around the stamp
    private const long Step = 1200; // h100: vertical step between candidates
    private const int Steps = 100; // at most this many steps up per column

    /// <summary>
    /// Candidate positions in trial order: requested (x, y); mirrored (vw − x − w, y); then up the requested column
    /// y + k·step (k = 1…, while y + k·step + h ≤ vh − y, k ≤ 100); then up the mirrored column. The mirrored column is
    /// left out when it equals the requested one.
    /// </summary>
    public static List<(long X, long Y)> Candidates(long vw, long vh, long x, long y, long w, long h)
    {
        long xl = vw - x - w;
        var o = new List<(long, long)> { (x, y) };
        if (xl != x) o.Add((xl, y));
        var cols = xl != x ? new[] { x, xl } : new[] { x };
        foreach (var cx in cols)
            for (int k = 1; k <= Steps && y + k * Step + h <= vh - y; k++)
                o.Add((cx, y + k * Step));
        return o;
    }

    /// <summary>
    /// The first candidate whose /Rect, grown by Pad on every side, overlaps no occupied box (strict overlap: touching
    /// edges are free). Ok = false → none is free (the caller keeps the requested rect).
    /// </summary>
    public static (long X, long Y, bool Ok) Place(long[] box, int rot, long x, long y, long w, long h, List<long[]> occ)
    {
        long vw = box[2] - box[0], vh = box[3] - box[1];
        if (rot is 90 or 270) (vw, vh) = (vh, vw);
        foreach (var (cx, cy) in Candidates(vw, vh, x, y, w, h))
        {
            long[] r;
            try
            {
                r = SignatureAppearance.Rect(box, rot, cx, cy, w, h);
            }
            catch (AppearanceException)
            {
                continue;
            }
            if (Free(r, occ)) return (cx, cy, true);
        }
        return (x, y, false);
    }

    /// <summary>
    /// Go placeFree: r (user space, h100) grown by Pad on every side overlaps no occupied box (strict overlap: touching
    /// edges are free).
    /// </summary>
    private static bool Free(long[] r, List<long[]> occ)
    {
        long e0 = r[0] - Pad, e1 = r[1] - Pad, e2 = r[2] + Pad, e3 = r[3] + Pad;
        foreach (var b in occ)
            if (b[0] < e2 && e0 < b[2] && b[1] < e3 && e1 < b[3]) return false;
        return true;
    }

    /// <summary>
    /// Go core.PlaceOnPage — PLACEMENT_SPEC.md §6 on a page whose geometry is known and whose requested rect is inside it:
    /// scan the page and choose the stamp position. exact (§6a) → the requested rect is the only candidate (never moved):
    /// requested when free, overlap when not.
    /// </summary>
    public static PlaceResult Choose(PdfValue page, long[] box, int rot, long x, long y, long w, long h, bool exact)
    {
        var occ = Occupancy.Scan(page, box);
        if (occ is null) return new PlaceResult(x, y, PlacementStatus.Unscanned);
        if (exact)
        {
            bool free;
            try
            {
                free = Free(SignatureAppearance.Rect(box, rot, x, y, w, h), occ);
            }
            catch (AppearanceException)
            {
                free = false;
            }
            return new PlaceResult(x, y, free ? PlacementStatus.Requested : PlacementStatus.Overlap);
        }
        var (px, py, ok) = Place(box, rot, x, y, w, h, occ);
        if (!ok) return new PlaceResult(x, y, PlacementStatus.Overlap);
        if (px != x || py != y) return new PlaceResult(px, py, PlacementStatus.Moved);
        return new PlaceResult(x, y, PlacementStatus.Requested);
    }
}
