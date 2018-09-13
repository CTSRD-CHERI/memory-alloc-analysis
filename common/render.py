from PIL import ImageDraw

# Takes an iterator producing (base, length, color) triples and produces an
# image of szx * szy pixels.  base >= szx * szy will be discarded.
def renderSpans(img, it) :
    (szx, szy) = img.size
    imgd = ImageDraw.Draw(img)

    for (loc, sz, c) in it :
        (ipy, ipx) = (int(loc / szx), loc % szx)
        (fpy, fpx) = (int((loc + sz - 1)/szx), (loc + sz - 1) % szx)

        if ipy > szy : continue
        if fpy > szy : (fpy, fpx) = (szy, szx)

        if ipy == fpy :
            # Fits entirely within one column
            imgd.line([(ipx,ipy), (fpx,fpy)], fill=c)
        else :
            # Draw initial, final, and middle spans
            imgd.line([(ipx,ipy), (szx,ipy)], fill=c)
            imgd.line([(0,fpy), (fpx,fpy)], fill=c)
            if fpy > ipy+1 :
                imgd.rectangle([(0,ipy+1),(szx,fpy-1)], fill=c)

# Like the above, but uses a Z-order curve of horizontal size 2**p2.
def renderSpansZ(img, p2, it) :
    assert p2 <= 32, "Z-order too big"

    imgd = ImageDraw.Draw(img)
    botmask = (1 << (2 * p2)) - 1

    for (b, sz, c) in it :
        # We could surely do better, but this suffices for now
        for loc in range(b, b+sz) :
            bot = loc & botmask
            top = (loc >> (2 * p2)) << p2

            # Z slice
            x = bot            & 0x55555555
            x = (x | (x >> 1)) & 0x33333333
            x = (x | (x >> 2)) & 0x0f0f0f0f
            x = (x | (x >> 4)) & 0x00ff00ff
            x = (x | (x >> 8)) & 0x0000ffff

            y = (bot >> 1)     & 0x55555555
            y = (y | (y >> 1)) & 0x33333333
            y = (y | (y >> 2)) & 0x0f0f0f0f
            y = (y | (y >> 4)) & 0x00ff00ff
            y = (y | (y >> 8)) & 0x0000ffff

            imgd.point([x, top+y], fill=c)
