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
